package com.szxmd.fangtan.util;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;

import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

public class DesUtil {

	public final static String DES = "DES";
	private final static String ENCODE = "UTF8";

	public static void main(String[] args) throws Exception {
		String data = "425123047@qq.com";
		String key = "苏州橡木盾信息技术有限公司";
		System.out.println(encrypt(data, key));
		String hh = "SzXwdWpATLCySA2hHAByJEet2xWgJ3k4";
		// System.out.println(hh.get);
		// System.out.println(decrypt(hh, key));
		System.out.println(decrypt(encrypt(data, key), key));
		// SzXwdWpATLCySA2hHAByJEet2xWgJ3k4
	}

	/**
	 * 根据键值进行加密
	 * 
	 * @param data
	 *            需要加密的源数据
	 * @param key
	 *            加密键byte的数组
	 * @return
	 */
	public static String encrypt(String data, String key) throws Exception {
		byte[] bt = encrypt(data.getBytes(ENCODE), key.getBytes(ENCODE));
		String strs = new BASE64Encoder().encode(bt);
		return strs;
	}

	/**
	 * 根据兼职进行解密
	 * 
	 * @param data
	 *            需要加密的源数据
	 * @param key
	 *            加密键的密钥
	 * @return
	 * @throws InvalidKeyException
	 * @throws Exception
	 */
	public static byte[] encrypt(byte[] data, byte[] key) throws InvalidKeyException, Exception {
		// 1.生成一个可信任的随机数源
		SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");

		// 2.从原始密钥数据创建DESkeySpec对象
		DESKeySpec dks = new DESKeySpec(key);

		// 3.创建一个密钥工厂.然后用它吧DESKeySpec转换成SecretKey对象
		SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(DES);
		SecretKey securekey = keyFactory.generateSecret(dks);

		// 4.Cipher对象实际完成加密操作
		Cipher cipher = Cipher.getInstance(DES);

		// 5.用密钥初始化Cipher对象
		cipher.init(Cipher.ENCRYPT_MODE, securekey, sr);

		return cipher.doFinal(data);
	}

	/**
	 * 根据键值进行解密
	 * 
	 * @param data
	 *            解密的数据
	 * @param key
	 *            加密键byte数组
	 * @return
	 * @throws IOException
	 * @throws Exception
	 */
	public static String decrypt(String data, String key) throws IOException, Exception {
		if (data == null) {
			return null;
		}
		BASE64Decoder decoder = new BASE64Decoder();
		byte[] buf = decoder.decodeBuffer(data);
		byte[] bt = decrypt(buf, key.getBytes(ENCODE));
		return new String(bt, ENCODE);
	}

	/**
	 * 根据键值进行解密
	 * 
	 * @param data
	 * @param key
	 * @return
	 * @throws Exception
	 */
	public static byte[] decrypt(byte[] data, byte[] key) throws Exception {
		// 1.生成一个可信任的随机数源
		SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");

		// 2.从原始密钥数据创建DESKeySpec对象
		DESKeySpec dks = new DESKeySpec(key);

		// 3.创建一个密钥工厂
		SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(DES);
		SecretKey securekey = keyFactory.generateSecret(dks);

		// 4.Cipher 对象实际完成解密操作;
		Cipher cipher = Cipher.getInstance(DES);

		// 5.用密钥初始化Cipher对象
		cipher.init(Cipher.DECRYPT_MODE, securekey, sr);
		return cipher.doFinal(data);
	}
}
