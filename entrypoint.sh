#!/bin/bash

# Run pipenv commands
echo  "Hello Starlink LAB"
# Execute the CMD passed to the container
exec "$@"
