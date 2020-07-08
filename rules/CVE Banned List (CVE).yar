/*
    Tests for instances of Banned CVEs.
*/

rule CVE001 : CVE_2017_0144
{
    meta:
        author = "Joocer"
        description = "Reports should not have Critical CVEs (CVE-2017-0144)"
        timestamp = "2020-07-08"
        version = "0.02"
        importance = "high"
        reference = "https://github.com/joocer/ytf/blob/master/Refs/CVE%20Banned%20List.md"
                
    strings: 
        $cve = "CVE-2017-0144"
        
    condition: 
        not $cve
}

rule CVE002 : CVE_2017_5638
{
    meta:
        author = "Joocer"
        description = "Reports should not have Critical CVEs (CVE-2017-5638)" 
        timestamp = "2020-07-08"
        version = "0.02"
        importance = "high"
        reference = "https://github.com/joocer/ytf/blob/master/Refs/CVE%20Banned%20List.md"
                
    strings: 
        $cve = "CVE-2017-5638"
        
    condition: 
        not $cve
}