/*
    Tests for the existance of HTTP Headers.
*/

rule HTTPH001 : ASVSx_x CWEx
{
    meta:
        version = 20200705
        description = "HTTP Response Headers should include CORS Header"
        impact = 4
        author = "390516"
                
    strings: 
        $a = "Access-Control-Allow-Origin:" nocase
        
    condition: 
        $a
}


rule HTTPH002 : ASVSx_x CWEx
{
    meta:
        version = 20200705
        description = "HTTP Response Headers should include HTST Header"
        impact = 7
        author = "390516"
                
    strings: 
        $a = /strict-transport-security:[\s]max-age=[0-9]+/ nocase
        
    condition: 
        $a
}