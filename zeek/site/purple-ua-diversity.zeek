##! UA diversity detector — flag a single src emitting too many distinct
##! HTTP User-Agent strings in a short window.
##!
##! Rationale: a legitimate client (browser, single tool) emits one UA
##! consistently. Attacker tooling that rotates UA headers to evade
##! signatures (e.g. ART T1071.001 #3 malicious-UA-fanout) or scanners
##! that impersonate multiple browsers will spike UA diversity.
##!
##! Durability: catches the TECHNIQUE not a specific UA string. Immune to
##! version bumps of any individual tool. Skilled attackers can still
##! evade by keeping UA constant, but then signature rules on that UA
##! would catch them (defense in depth).
##!
##! Tuning:
##!   PurpleAgent::ua_diversity_threshold  (default 3) — alert when src
##!     has sent MORE than N unique UAs
##!   PurpleAgent::ua_diversity_window     (default 60s) — sliding window
##!
##! Output: emits PurpleAgent::UA_Diversity_Spike notice.

@load base/frameworks/notice
@load base/protocols/http

module PurpleAgent;

export {
	redef enum Notice::Type += {
		## A single source IP emitted more than `ua_diversity_threshold`
		## distinct User-Agent strings within `ua_diversity_window`.
		UA_Diversity_Spike,
	};

	const ua_diversity_threshold: count = 3 &redef;
	const ua_diversity_window: interval = 60 sec &redef;
}

global seen_uas_by_src: table[addr] of set[string]
	&create_expire=60sec;

event http_header(c: connection, is_orig: bool, name: string, value: string)
	{
	if ( ! is_orig ) return;
	# Header names arrive uppercased already in modern Zeek, but be defensive.
	if ( to_upper(name) != "USER-AGENT" ) return;

	local src = c$id$orig_h;

	if ( src !in seen_uas_by_src )
		seen_uas_by_src[src] = set();

	add seen_uas_by_src[src][value];

	if ( |seen_uas_by_src[src]| > ua_diversity_threshold )
		{
		NOTICE([
			$note = UA_Diversity_Spike,
			$msg  = fmt("%s emitted %d distinct User-Agents within %s window (threshold %d)",
			            src, |seen_uas_by_src[src]|,
			            ua_diversity_window, ua_diversity_threshold),
			$sub  = fmt("UAs: %s", seen_uas_by_src[src]),
			$conn = c,
			$identifier = fmt("ua-diversity-%s", src),
			$suppress_for = 10 mins
		]);
		# Drop the entry so a sustained spike gives at most one notice
		# per suppression window (above) rather than one per new UA.
		delete seen_uas_by_src[src];
		}
	}
