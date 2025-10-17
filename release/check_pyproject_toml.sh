#!/bin/bash
echo "Checking for deps in pyproject.toml"
echo "Running uv sync.."
uv sync
RED='\033[0;31m'
NC='\033[0m' # No Color
OBS_PROJECTS="home:jordimassaguerpla:branch:systemsmanagement:Uyuni:AI science:machinelearning:mcp devel:languages:python"
changes=0
for i in $(uv pip list | tail -n 41 | cut -d" " -f1);do
  grep $i pyproject.toml > /dev/null
  if [ $? -ne 0 ];then # package not in pyproject
    found="FALSE"
    echo
    echo "$i not found in pyproject.toml"
    version_i=$(uv pip show $i | grep Version: | cut -d ":" -f2 | tr -s " " | cut -d" " -f2)
    echo "We need $i-$version_i (installed with uv/pip)"
    for p in $OBS_PROJECTS;do
      echo "Looking for python-$i in $p..."
      osc ls $p python-$i > /dev/null 2> /dev/null
      if [ $? -ne 0 ];then # package was not found
        echo "python-$i not found in obs://$p"
      else # package was found
        echo "python-$i found in obs://$p"
        version_p=$(osc cat $p python-$i python-$i.spec | grep Version: | cut -d":" -f2 | tr -s " " | cut -d" " -f2)
        echo "python-$i-$version_p in obs://$p"
        if [ "$version_i" == "$version_p" ];then
          echo "You can use the package from obs://$p"
    	  uv add $i==$version_i
        else # versions do not match
          echo "Installed version $version_i differ from packaged version $version_p in obs://$p. Trying to change installed version..."
          uv add $i==$version_p
          if [ $? -ne 0 ];then
            printf "${RED}I could not install $version_p. You need to change the package version in $p to $version_i ${NC}\n"
          fi # install error?
        fi # do versions not match?
        found="TRUE"
        break # package was found, no need to check more projects 
      fi # was package found?
    done # loop projects
    if [ "$found" == "FALSE" ];then
      changes=$((changes+1))
      printf "${RED}Package $i was not found in $OBS_PROJECTS. You need to create a new package ${NC}\n"
    fi # package not found
  fi # package in pyproject
done # loop installed packages
if [ $changes -eq 0 ];then
  echo "Nothing to do"
fi

