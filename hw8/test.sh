#! /bin/bash

for i in {1..10}; do
        curl -s -o /dev/null -w "%{http_code}\n" http://localhost/ &
done
wait