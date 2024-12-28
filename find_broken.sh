TMP_FILE=$(mktemp)

# find "." -type f -name "*.md" -size -4 -print > $TMP_FILE

find . -type f -iname "*.md" | while read -r file; do
    whitespaces=$(grep -o '[[:space:]]' "$file" | wc -l)
    non_whitespaces=$(grep -o '[^[:space:]]' "$file" | wc -l)
    if [ "$whitespaces" -gt "$non_whitespaces" ]; then
        echo $file >> $TMP_FILE
    fi
done

cat $TMP_FILE | while read line; do
    REPO=$(echo $line | cut -d'/' -f3)
    TYPE=$(echo $line | cut -d'/' -f2)
    grep -E "$TYPE.*/$REPO" origin_repos.txt >> redo_repos.txt
done

cat redo_repos.txt | sort -u -o redo_repos.txt

cat $TMP_FILE | while read line; do
    echo $line | cut -d'/' -f1-3 | xargs -I {} rm -rf {}
done

rm $TMP_FILE