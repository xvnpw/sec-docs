TMP_FILE=$(mktemp)

find "." -type f -name "*.md" -size -4 -print > $TMP_FILE

cat $TMP_FILE | while read line; do
    REPO=$(echo $line | cut -d'/' -f3)
    grep $REPO origin_repos.txt >> redo_repos.txt
done

cat redo_repos.txt | sort -u -o redo_repos.txt

cat $TMP_FILE | while read line; do
    echo $line | cut -d'/' -f1-3 | xargs -I {} rm -rf {}
done

rm $TMP_FILE