#!/bin/bash
set -e
mkdir -p out
javac -d out src/main/java/com/cloudforensics/Main.java
exec java -cp out com.cloudforensics.Main
