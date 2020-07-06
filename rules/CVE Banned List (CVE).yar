/*
    Tests for instances of Banned CVEs.
*/

rule CVE001 : CVE_2000_0001
{
    meta:
        version = 20200705
        description = "Reports should not have Critical CVEs (CVE-2000-0001)"
        impact = 10     // the impact of failure 0 to 10
        author = "Joocer"
                
    strings: 
        $cve = "CVE-2000-0001"
        
    condition: 
        not $cve
}

rule CVE002 : CVE_2001_0002
{
    meta:
        version = 20200705
        description = "Reports should not have Critical CVEs (CVE-2001-0002)" 
        impact = 10     // the impact of failure 0 to 10
        author = "Joocer"
                
    strings: 
        $cve = "CVE-2001-0002"
        
    condition: 
        not $cve
}