#!/bin/bash

# Sort first by URL (column 2), then by language (column 1)
sort -k2,2 -k1,1 origin_repos.txt |
# Group by URL and print only if there are multiple entries
awk '{
    url = $2
    lang = $1
    urls[url] = urls[url] ? urls[url] "\n" lang : lang
}
END {
    for (url in urls) {
        if (urls[url] ~ /\n/) {  # If contains newline, means multiple entries
            print "Repository:", url
            print "Languages:", urls[url]
            print "---"
        }
    }
}'