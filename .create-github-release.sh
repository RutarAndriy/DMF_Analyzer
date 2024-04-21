#!/bin/bash

name=$1
version=$2
echo Creating GitHub release v$version for \"$name\" project

titleMessage="${name//_/ } v$version"
notesMessage="Version $version"

jarDef="./target/$name-$version.jar"
jarFat="./target/$name-$version-jar-with-dependencies.jar"
jarDoc="./target/$name-$version-javadoc.jar"

gh release create v$version --title "$titleMessage" --notes "$notesMessage" $jarDef $jarFat $jarDoc

