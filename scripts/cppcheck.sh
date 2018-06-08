#!/bin/sh

cppcheck --quiet --enable=all -f . 2>warnings.$$
grep -v bounds warnings.$$ | grep -v Skipping | grep -v is\ never\ used | grep -v scanf | grep -v check-config | grep -v reassigned
rm -f warnings.$$
