---
layout: post
title: C# 关于兼容Java X509方式导出公钥的代码
---

  工作中碰到了对接大华平台的时候，给出的Java示例代码像这样:

```java
    /**
	 * 加密<br>
	 * 用公钥加密
	 * 
	 * @param data
	 * @param key
	 * @return
	 * @throws Exception
	 */
	public static byte[] encryptByPublicKey(byte[] data, String key)
			throws Exception {
		// 对公钥解密
		byte[] keyBytes = decryptBASE64(key);

		// 取得公钥
		X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(keyBytes);
		KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
		Key publicKey = keyFactory.generatePublic(x509KeySpec);

		// 对数据加密
		Cipher cipher = Cipher.getInstance(PADDING ,  BouncyCastleProvider.PROVIDER_NAME);
		cipher.init(Cipher.ENCRYPT_MODE, publicKey);

		return cipher.doFinal(data);
	}
```
  使用接口提供的publicKey对Pass加密，然后进行登录操作。
当我在C#里尝试解析publicKey时，我发现C#并没有方法可以解析，原因是Java和.NET支持不同的标准。Java的X509EncodedKeySpec实际上是X.509标准中的SubjectPublicKeyInfo对象。而 . Net Core 3.0 以上时，可能提供了一个API`ImportSubjectPublicKeyInfo`来导入公钥（我并没有尝试过）。也就是说对于. Net Framework，无法通过只包含publicKey的证书来构造RSA对象。  

  在StackOverfolw上的讨论在[这里](https://stackoverflow.com/questions/52406728/what-is-equivalent-of-x509encodedkeyspec-in-c-sharp)。当然其实这个问题在谷歌上能找到更多的讨论，这里就不贴地址了，显然我无法改变大华平台来更改导出的方式。  

  既然C#不提供这样的方法，只能自己造轮子了，造这个轮子需要两个知识点。  
1.对SubjectPublicKeyInfo结构的理解  
2.对结构转数组的方式——DER有所了解  
  幸运的是，微软已经提供了很多资料，来[看看](https://docs.microsoft.com/zh-cn/windows/win32/seccertenroll/about-sequence)。

```
30 81 9f                             ; SEQUENCE (9f Bytes)
|  30 0d                             ; SEQUENCE (d Bytes)
|  |  |  06 09                       ; OBJECT_ID (9 Bytes)
|  |  |  2a 86 48 86 f7 0d 01 01 01  ; 1.2.840.113549.1.1.1 
|  |  05 00                          ; NULL (0 Bytes)
|  03 81 8d                          ; BIT_STRING (8d Bytes)
|     00
|     30 81 89                       ; SEQUENCE (89 Bytes)
|        02 81 81                    ; INTEGER (81 Bytes)
|        |  00
|        |  8f e2 41 2a 08 e8 51 a8  8c b3 e8 53 e7 d5 49 50
|        |  b3 27 8a 2b cb ea b5 42  73 ea 02 57 cc 65 33 ee
|        |  88 20 61 a1 17 56 c1 24  18 e3 a8 08 d3 be d9 31
|        |  f3 37 0b 94 b8 cc 43 08  0b 70 24 f7 9c b1 8d 5d
|        |  d6 6d 82 d0 54 09 84 f8  9f 97 01 75 05 9c 89 d4
|        |  d5 c9 1e c9 13 d7 2a 6b  30 91 19 d6 d4 42 e0 c4
|        |  9d 7c 92 71 e1 b2 2f 5c  8d ee f0 f1 17 1e d2 5f
|        |  31 5b b1 9c bc 20 55 bf  3a 37 42 45 75 dc 90 65
|        02 03                       ; INTEGER (3 Bytes)
|           01 00 01
```

这个结构就是经过DER编码后的SubjectPublicKeyInfo结构了，我们就是要从这里面提取需要的东西。简单的讲解一下DER，DER是一种TLV结构体，也就是由`Type`,`Length`,`Value`组成的结构体，`Type`有很多类型，可以在上面的微软网页中找到，重点在于`Length`，在DER中，`Length`是一个字节，`0000 0000`,指示后面`Value`的长度,如果`Value`大于127字节，则置最高位为1，后面的6-0指示要用多少字节来表示长度。如果`Value`小于127字节，则最高位为0，后面的6-0位标识长度（其实就是长度本身了）。如果还不明白，可以再看看微软的网页。随后从后面读取`Value`即可。

以上面的例子来说，开头的`0x30`标识后面的数据是一个结构体，而`0x81`等于`1000 0001`指示数据大于127字节，长度将在后面的一个字节表示，即`0x9f`。

下面给出我的代码，希望有所启发吧,我构造了`DER`类用来解析DER结构，只暴露一个`ReadValue()`方法，以此来封装内部对于DER的处理。随后构造`SubjectPublicKeyInfo`类来使用DER解析公钥数组，最后返回RSA所使用的模数和指数。

感谢收看。
```CSharp

namespace DH.Secuirity
{
    public static class RSA
    {
        /// <summary>
        /// 平台PublicKey加密Pass方法
        /// </summary>
        /// <param name="base64">此公钥应为 Base64 字符串类型</param>
        /// <param name="s"></param>
        /// <returns></returns>
        public static string X509Encrypt(string base64, string s, Encoding encoding = null)
        {
            if (encoding == null)
                encoding = Encoding.Default;
            var x509Key = Convert.FromBase64String(base64);
            var subjectPublicKeyInfo = new SubjectPublicKeyInfo(x509Key);
            var publicKey = subjectPublicKeyInfo.GetPublicKey();

            using (var rsa = new RSACryptoServiceProvider())
            {
                RSAParameters parameters = new RSAParameters()
                {
                    Modulus = publicKey.Item1,
                    Exponent = publicKey.Item2
                };
                rsa.ImportParameters(parameters);
                var encrypted = rsa.Encrypt(encoding.GetBytes(s), false);
                return Convert.ToBase64String(encrypted);
            }
        }

        /// <summary>
        /// DER解析
        /// </summary>
        public class DER : IDisposable
        {
            private bool disposedValue;
            private BinaryReader reader;

            public DER(byte[] bytes)
            {
                MemoryStream stream = new MemoryStream(bytes);
                reader = new BinaryReader(stream);
            }

            public bool CanRead => reader.BaseStream.Position < reader.BaseStream.Length;

            private ValueType ReadType()
            {
                return (ValueType)reader.ReadByte();
            }

            private int ReadLength()
            {
                int length = reader.ReadByte();

                //检查第7位是否是1，如果是，则指示该内容长度大于127字节，则此字节6-0为实际的内容占用的字节
                if ((length & 0b10000000) == 0b10000000)
                {
                    //获取长度字节的长度
                    int count = length & 0b01111111;
                    byte[] bytes = new byte[count];

                    //指向内容的长度
                    reader.Read(bytes, 0, bytes.Length);

                    //翻转顺序
                    Array.Reverse(bytes);
                    length = LengthBytesToInt(bytes);
                }

                return length;
            }

            /// <summary>
            /// 根据文档显示，长度不应该超过 256^126 ，即两个字节
            /// </summary>
            /// <param name="lengthBytes"></param>
            /// <returns></returns>
            private int LengthBytesToInt(byte[] lengthBytes)
            {
                if (lengthBytes.Length > 2)
                    throw new NotSupportedException($"length {lengthBytes.Length} too big.");
                int value = 0;
                for (int i = 0; i < lengthBytes.Length; i++)
                {
                    value = (value << 8) | lengthBytes[i];
                }
                return value;
            }

            public ValueTuple<ValueType, byte[]> ReadValue()
            {
                ValueType type = ReadType();
                byte[] value = new byte[ReadLength()];
                reader.Read(value, 0, value.Length);
                ValueTuple<ValueType, byte[]> wrapper = new ValueTuple<ValueType, byte[]>(type, value);
                return wrapper;
            }

            public enum ValueType
            {
                BOOLEAN = 0x01,
                INTEGER = 0x02,
                BIT_STRING = 0x03,
                OCTET_STRING = 0x04,
                NULL = 0x05,
                OBJECT_IDENTIFIER = 0x06,
                UTF8String = 0x0c,
                PrintableString = 0x13,
                TeletexString = 0x14,
                IA5String = 0x16,
                BMPString = 0x1e,
                SEQUENCE = 0x30,
                SET = 0x31
            }

            protected virtual void Dispose(bool disposing)
            {
                if (!disposedValue)
                {
                    if (disposing)
                    {
                        // TODO: 释放托管状态(托管对象)
                        reader.Dispose();
                    }

                    // TODO: 释放未托管的资源(未托管的对象)并替代终结器
                    // TODO: 将大型字段设置为 null
                    disposedValue = true;
                }
            }

            // // TODO: 仅当“Dispose(bool disposing)”拥有用于释放未托管资源的代码时才替代终结器
            // ~SubjectPublicKeyInfo()
            // {
            //     // 不要更改此代码。请将清理代码放入“Dispose(bool disposing)”方法中
            //     Dispose(disposing: false);
            // }

            public void Dispose()
            {
                // 不要更改此代码。请将清理代码放入“Dispose(bool disposing)”方法中
                Dispose(disposing: true);
                GC.SuppressFinalize(this);
            }
        }

        /// <summary>
        /// 兼容 Java X.509 SubjectPublicKeyInfo DER
        /// </summary>
        public class SubjectPublicKeyInfo
        {
            private DER der;
            private readonly byte[] RSA_OID = new byte[] { 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01 };

            public SubjectPublicKeyInfo(byte[] derBytes)
            {
                der = new DER(derBytes);
            } 

            /// <summary>
            /// 获取公钥
            /// </summary>
            /// <returns>modulus and exponent 返回模数和指数</returns>
            public ValueTuple<byte[], byte[]> GetPublicKey()
            {
                //获取主序列
                var wrapper1 = der.ReadValue();
                if (wrapper1.Item1 != DER.ValueType.SEQUENCE)
                {
                    throw new InvalidDataException();
                }
                var sequence1 = new DER(wrapper1.Item2);
                var wrapper2 = sequence1.ReadValue();

                //检查第一个结构体是否存在
                if (wrapper2.Item1 != DER.ValueType.SEQUENCE)
                {
                    throw new InvalidDataException();
                }

                var sequence2 = new DER(wrapper2.Item2);
                var wrapper3 = sequence2.ReadValue();
                if (wrapper3.Item1 != DER.ValueType.OBJECT_IDENTIFIER)
                {
                    throw new InvalidDataException();
                }

                if (Enumerable.SequenceEqual(wrapper3.Item2, RSA_OID) == false)
                {
                    throw new InvalidDataException();
                }

                var wrapper4 = sequence1.ReadValue();
                if (wrapper4.Item2.First() != 0x00)
                {
                    throw new InvalidDataException();
                }

                //这里有个不明意义的0x00
                var sequence3 = new DER(wrapper4.Item2.Skip(1).ToArray());
                var wrapper5 = sequence3.ReadValue();
                if (wrapper5.Item1 != DER.ValueType.SEQUENCE)
                {
                    throw new InvalidDataException();
                }

                var sequence4 = new DER(wrapper5.Item2);
                var wrapper6 = sequence4.ReadValue();
                if (wrapper6.Item1 != DER.ValueType.INTEGER)
                {
                    throw new InvalidDataException();
                }
                var integer1 = wrapper6.Item2.First() == 0x00 ? wrapper6.Item2.Skip(1).ToArray() : wrapper6.Item2;

                var wrapper7 = sequence4.ReadValue();
                if (wrapper7.Item1 != DER.ValueType.INTEGER)
                {
                    throw new InvalidDataException();
                }

                var integer2 = wrapper7.Item2;

                return new ValueTuple<byte[], byte[]>(integer1, integer2);
            }
        }

        ///struct from https://docs.microsoft.com/zh-cn/windows/win32/seccertenroll/about-sequence
        ///
        //30 81 9f                             ; SEQUENCE (9f Bytes)
        //|  30 0d                             ; SEQUENCE (d Bytes)
        //|  |  |  06 09                       ; OBJECT_ID (9 Bytes)
        //|  |  |  2a 86 48 86 f7 0d 01 01 01  ; 1.2.840.113549.1.1.1 
        //|  |  05 00                          ; NULL (0 Bytes)
        //|  03 81 8d                          ; BIT_STRING (8d Bytes)
        //|     00
        //|     30 81 89                       ; SEQUENCE (89 Bytes)
        //|        02 81 81                    ; INTEGER (81 Bytes)
        //|        |  00
        //|        |  8f e2 41 2a 08 e8 51 a8  8c b3 e8 53 e7 d5 49 50
        //|        |  b3 27 8a 2b cb ea b5 42  73 ea 02 57 cc 65 33 ee
        //|        |  88 20 61 a1 17 56 c1 24  18 e3 a8 08 d3 be d9 31
        //|        |  f3 37 0b 94 b8 cc 43 08  0b 70 24 f7 9c b1 8d 5d
        //|        |  d6 6d 82 d0 54 09 84 f8  9f 97 01 75 05 9c 89 d4
        //|        |  d5 c9 1e c9 13 d7 2a 6b  30 91 19 d6 d4 42 e0 c4
        //|        |  9d 7c 92 71 e1 b2 2f 5c  8d ee f0 f1 17 1e d2 5f
        //|        |  31 5b b1 9c bc 20 55 bf  3a 37 42 45 75 dc 90 65
        //|        02 03                       ; INTEGER (3 Bytes)
        //|           01 00 01
    }
}
```