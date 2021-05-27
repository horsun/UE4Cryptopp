# UE4Cryptopp
基于cryptopp v8.2 开发的UE4加密库，支持Android 和Windows平台,在UE 4.23版本测试没问题

# 坑
在编译安卓环境的时候没少遇到坑，先是`try catch`的打包问题，在windows下还能解决，直接在build.cs加一行`bEnableExceptions = true;`
再就是RTTI的问题，就是库里面用了`throw、typeid()、dynamic_cast()`等功能，这个就有点麻烦，要将库方法和虚幻尽量的隔绝开来，三方库单独分出一个Module，需要和虚幻对象操作的再写一个Module。
再有就是Cryptopp在打包android so文件的麻烦了，各种环境在windows折腾了半天，最后在Ubuntu直接一波成，无语，不懂为什么不直接提供打包好的文件。
