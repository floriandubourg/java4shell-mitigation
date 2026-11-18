```bash
mkdir -p /tmp/java4shell-validation
javac --release 8 -d /tmp/java4shell-validation LiveProbe.java
java -cp /tmp/java4shell-classes LiveProbe 600
```

This can also be use to test if the JVM patch works
