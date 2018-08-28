basepath=$(cd `dirname $0`; pwd)
agentpath=$basepath/libdeclass.so
encoderpath=$basepath/encoder.so
cmdpath=$agentpath=$encoderpath
echo $cmdpath
java -agentpath:$cmdpath Hello
