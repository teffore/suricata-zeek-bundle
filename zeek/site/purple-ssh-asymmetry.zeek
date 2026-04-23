##! Bulk SSH exfil detector — flag SSH connections with strongly
##! asymmetric byte counts, indicative of scp / tar-over-SSH /
##! rsync-over-SSH pushes.
##!
##! Rationale: a shell session is roughly symmetric in traffic
##! (keystrokes out, small output in). An scp push or tar|ssh pipe
##! pushes megabytes from the client with a tiny server ack stream.
##! Since SSH is encrypted, no payload signature can catch this;
##! flow shape is the only lever.
##!
##! Tunables:
##!   ssh_exfil_min_orig_bytes  (default 1 MB) — ignore tiny flows
##!   ssh_exfil_max_resp_ratio  (default 0.05) — flag if resp/orig < this
##!
##! Durability: catches the BEHAVIOR (bulk upload over SSH). Immune to
##! tool substitution (scp, rsync, tar|ssh, sftp all look the same on
##! the wire). A clever attacker could throttle or pad to evade; those
##! countermeasures slow the exfil, which is its own cost.
##!
##! Output: PurpleAgent::SSH_Bulk_Exfil_Candidate notice.

@load base/frameworks/notice
@load base/protocols/ssh

module PurpleAgent;

export {
	redef enum Notice::Type += {
		## SSH connection closed with strongly asymmetric bytes,
		## suggesting bulk upload (scp, tar|ssh, rsync over SSH).
		SSH_Bulk_Exfil_Candidate,
	};

	const ssh_exfil_min_orig_bytes: count    = 1048576 &redef;  # 1 MiB
	const ssh_exfil_max_resp_ratio: double   = 0.05 &redef;
}

event connection_state_remove(c: connection)
	{
	# Only look at flows the SSH analyzer successfully attached to.
	if ( ! c?$ssh ) return;

	# Byte counts come from the connection record (conn.log fields).
	if ( ! c?$conn ) return;
	if ( ! c$conn?$orig_bytes || ! c$conn?$resp_bytes ) return;

	local ob = c$conn$orig_bytes;
	local rb = c$conn$resp_bytes;

	if ( ob < ssh_exfil_min_orig_bytes ) return;

	# Ratio is resp/orig; small ratio = highly asymmetric push.
	local ratio: double = rb == 0 ? 0.0 : (rb + 0.0) / ob;
	if ( ratio > ssh_exfil_max_resp_ratio ) return;

	local dur = c$conn?$duration ? fmt("%s", c$conn$duration) : "?";
	NOTICE([
		$note = SSH_Bulk_Exfil_Candidate,
		$msg  = fmt("SSH bulk-upload flow: %s -> %s  orig=%d resp=%d ratio=%.4f dur=%s",
		            c$id$orig_h, c$id$resp_h, ob, rb, ratio, dur),
		$conn = c,
		$identifier = fmt("ssh-bulk-exfil-%s-%s", c$id$orig_h, c$id$resp_h),
		$suppress_for = 15 mins
	]);
	}
