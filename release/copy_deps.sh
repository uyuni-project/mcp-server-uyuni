projects="devel:languages:python science:machinelearning:mcp"
deps="systemsmanagement:Uyuni:AI:Deps"
for p in *;do
  echo "# deps for $p"
  cd $p
  for project in $projects;do
    for i in $(osc buildinfo 2>/dev/null | grep project=\"${project}\" | cut -d\" -f2 | grep python311 | tr -s "311-" "-");do
      echo "osc copypac -e ${project} ${i} ${deps}:${project}"
    done
  done
  cd ..
done
