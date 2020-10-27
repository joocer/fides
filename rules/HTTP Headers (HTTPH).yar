/*
    Tests for the existance of HTTP Headers.
*/

rule HTTPH001 : ASVSx_x CWEx
{
    meta:
        author = "Joocer"
        description = "HTTP Response Headers should include CORS Header"
        timestamp = "2020-07-08"
        version = "0.02"
        importance = "medium"
        reference = "https://github.com/joocer/ytf/blob/master/Refs/HTTP%20Headers.md"
                
    strings: 
        $a = "Access-Control-Allow-Origin:" nocase
        
    condition: 
        not $a
}


rule HTTPH002 : ASVSx_x CWEx
{
    meta:
        author = "Joocer"
        description = "HTTP Response Headers should include HTST Header"
        timestamp = "2020-07-08"
        version = "0.02"
        importance = "medium"
        reference = "https://github.com/joocer/ytf/blob/master/Refs/HTTP%20Headers.md"
                
    strings: 
        $a = /strict-transport-security:[\s]max-age=[0-9]*?/ nocase
        
    condition: 
        not $a
}
