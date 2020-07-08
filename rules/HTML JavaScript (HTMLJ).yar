/*
    HTML JavaScript Rules
*/

rule HTMLJ001 : ASVSx_x CWEx
{
    // Counts all script tages with an absolute source (starts HTTP(S)://)
    // Counts all script tages with an integrity attribute
    // Passes if the two counts are the same - this will be prone to false +ves

    meta:
        author = "Joocer"
        description = "Script tags should include SRI"
        timestamp = "2020-07-08"
        version = "0.02"
        importance = "medium"
        reference = "https://github.com/joocer/ytf/blob/master/Refs/HTML%20JavaScript.md"
                
    strings: 
        $has_script = /<script[\s\S]*?src="http(s)??:\/\/[\s\S]*?"[\s\S]*?>[\s\S]*?<\/script>/ nocase
        $has_sri = /<script[\s\S]*?integrity="[\s\S]*?"[\s\S]*?>[\s\S]*?<\/script>/ nocase 

    condition: 
        #has_script == #has_sri
}

rule HTMLJ002 : ASVSx_x CWEx
{    
    meta:
        author = "Joocer"
        description = "JavaScript Event triggers should not be in HTML tags"
        timestamp = "2020-07-08"
        version = "0.02"
        importance = "low"
        reference = "https://github.com/joocer/ytf/blob/master/Refs/HTML%20JavaScript.md"
                
    strings: 
        $has_on = /<\w*?[\s\S]*?\bon[\w]*?="[\s\S]*?>/ nocase
        $has_js = /<a[\s\S]*?href="javascript/ nocase

    condition: 
        not $has_on and
        not $has_js
}