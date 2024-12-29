while read -r line; do
  if ! grep -qi "$line" origin_repos.txt; then
    grep "$line" $1
  fi
done < <(cat $1 | cut -d' ' -f2)
