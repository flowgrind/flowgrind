#!/bin/bash
cd src/
mkdir -p new1 new2
for i in *.[hc]; do unexpand $i > new1/$i; done
mv new1/* .
for i in *.[hc]; do sed -e "s/[ \t]*$//" $i > new2/$i; done
mv new2/* .

rm new[12] -rf
rm new67890 -rf
cd ..
