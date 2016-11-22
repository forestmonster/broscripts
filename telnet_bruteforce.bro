##! Detect hosts performing Telnet bruteforcing.

@load base/frameworks/sumstats
@load base/frameworks/notice

module TelnetBruteforce;

export {
	redef enum Notice::Type += {
		## Indicates a host bruteforcing Telnet logins by totalling
		## connections to common Telnet ports.
		Bruteforcing,
	};

	## How many connections are required before we categorize
	## the activity as "bruteforcing."
	const bruteforce_threshold: double = 2 &redef;

	## The time period within which the threshold needs to be crossed before
	## being reset.
	const bruteforce_measurement_interval = 3mins &redef;
}

event bro_init()
	{
	local r1: SumStats::Reducer = [$stream="telnet.ports.conn", $apply=set(SumStats::UNIQUE), $unique_max=double_to_count(bruteforce_threshold+3)];
	SumStats::create([  $name="detect-telnet-bruteforcing",
						$epoch=bruteforce_measurement_interval,
						$reducers=set(r1),
						$threshold_val(key: SumStats::Key, result: SumStats::Result) =
							{
								return result["telnet.ports.conn"]$num+0.0;
							},
						$threshold=bruteforce_threshold,
						$threshold_crossed(key: SumStats::Key, result: SumStats::Result) =
							{
								local r = result["telnet.ports.conn"];
								local dur = duration_to_mins_secs(r$end-r$begin);
								local plural = r$unique>1 ? "s" : "";
								local message = fmt("%s made %d connection%s to %d Telnet server%s in %s", key$host, r$num, plural, r$unique, plural, dur);
								NOTICE([$note=TelnetBruteforce::Bruteforcing,
										$msg=message,
										$src=key$host,
										$identifier=cat(key$host)]);
							}
					]);
	}

event connection_established(c: connection)
	{
		if (    c$id$resp_p == 23/tcp     ||
				c$id$resp_p == 2323/tcp )
			{
				SumStats::observe("telnet.ports.conn", [$host=c$id$orig_h], [$str=cat(c$id$resp_h)]);
			}
	}
