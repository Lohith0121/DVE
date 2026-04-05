#!/bin/bash

backup_dirs=("/c/Users/rajas/Documents" "/c/Users/rajas/Favorites")
dest_dir="/d/New folder"
mkdir -p "$dest_dir"
backup_date=$(date +%b-%d-%y)
echo "Start of backup: ${backup_dirs[@]}"
for i in "${backup_dirs[@]}"; do
  name=$(basename "$i")
  tar -czf "/tmp/${name}-${backup_date}.tar.gz" "$i"
  if [ $? -eq 0 ]; then
    echo "$i backup success"
  else
    echo "$i backup fail"
  fi
  cp "/tmp/${name}-${backup_date}.tar.gz" "$dest_dir"
  if [ $? -eq 0 ]; then
    echo "copy success"
  else
    echo "copy fail"
  fi
done

rm /tmp/*.gz

echo "Backup is done"