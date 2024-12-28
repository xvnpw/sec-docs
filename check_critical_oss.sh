while read -r line; do
  if ! grep -qi "$line" origin_repos.txt; then
    grep "$line" critical_oss.txt
  fi
done < critical_oss_tmp1.txt
