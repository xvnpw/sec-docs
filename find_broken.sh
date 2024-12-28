TMP_FILE=$(mktemp)

find "." -type f -name "*.md" -size -4 -print > $TMP_FILE

cat $TMP_FILE | while read line; do
    REPO=$(echo $line | cut -d'/' -f3)
    grep $REPO origin_repos.txt >> redo_repos.txt
done

# cat $TMP_FILE | while read line; do
#     echo $line | xargs -I {} rm -r {}
# done

rm $TMP_FILE