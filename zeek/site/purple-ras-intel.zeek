##! Remote Access Software detection via TLS SNI substring match.
##!
##! Purpose: flag outbound TLS handshakes whose SNI contains any of a
##! curated set of Remote Access Software vendor domains (T1219).
##! Substring match so relay.anydesk.com, net.anydesk.com, etc. all hit
##! even though Zeek's Intel framework only does exact match.
##!
##! Durability notes:
##!   - Catches the default config of AnyDesk, TeamViewer, RustDesk,
##!     ScreenConnect, Splashtop, Atera, LogMeIn, NinjaRMM, Action1
##!   - Does NOT catch domain-fronted SNI (e.g. SNI=benign, Host=actual)
##!   - Does NOT catch IP-direct connections (no SNI)
##!   - Add new vendor domain strings to `ras_domain_substrings` to extend
##!
##! Output: emits PurpleAgent::Remote_Access_Software_SNI notice on match.

@load base/frameworks/notice

module PurpleAgent;

export {
	redef enum Notice::Type += {
		## A TLS ClientHello's SNI contained a known RAS vendor domain.
		Remote_Access_Software_SNI,
	};

	## Substring set of RAS vendor domains. Substring match — a single
	## entry like "anydesk.com" catches net.anydesk.com, relay.anydesk.com,
	## download.anydesk.com, etc.
	const ras_domain_substrings: set[string] = {
		"anydesk.com",
		"teamviewer.com",
		"rustdesk.com",
		"screenconnect.com",
		"splashtop.com",
		"atera.com",
		"ninjarmm.com",
		"logmein.com",
		"gotomypc.com",
		"gotoassist.com",
		"dameware.com",
		"radmin.com",
		"action1.com",
		"connectwise.com",
		"beyondtrust.com",
		"bomgarcloud.com",
	} &redef;
}

event ssl_extension_server_name(c: connection, is_orig: bool, names: string_vec)
{
	if ( ! is_orig ) return;
	if ( |names| == 0 ) return;

	local sni = names[0];
	for ( d in ras_domain_substrings )
		{
		if ( d in sni )
			{
			NOTICE([
				$note = Remote_Access_Software_SNI,
				$msg  = fmt("Remote Access Software SNI observed: %s (matched vendor: %s)",
				            sni, d),
				$sub  = sni,
				$conn = c,
				$identifier = fmt("ras-sni-%s-%s-%s",
				                  c$id$orig_h, c$id$resp_h, sni),
				$suppress_for = 10 mins
			]);
			break;
			}
		}
}
