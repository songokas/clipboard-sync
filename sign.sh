#!/bin/bash

cd dist

sum_name="SHA512SUMS"
sum_path="../target/$sum_name"

rm -f $sum_name
rm -f $sum_name.sig
> $sum_path
for f in *; do
    sha512sum "$f" >> $sum_path
done
cp $sum_path .
gpg --detach-sign --armor -o "$sum_name.sig" $sum_name
