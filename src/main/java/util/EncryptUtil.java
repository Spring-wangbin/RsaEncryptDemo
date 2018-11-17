package util;

import java.io.IOException;
import java.io.PrintStream;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * 放牛娃密码加密工具类
 * @author zhouyang
 *
 */
public class EncryptUtil {
	protected static Logger logger = LoggerFactory.getLogger(EncryptUtil.class);
	  private static final String MAC_NAME = "HmacSHA1";
	  private static final String ENCODING = "UTF-8";

	  public static String MD5(String input)
	  {
	    try
	    {
	      MessageDigest mdInst = MessageDigest.getInstance("MD5");

	      mdInst.update(input.getBytes());

	      byte[] md = mdInst.digest();

	      StringBuffer hexString = new StringBuffer();

	      for (int i = 0; i < md.length; ++i) {
	        String shaHex = Integer.toHexString(md[i] & 0xFF);
	        if (shaHex.length() < 2) {
	          hexString.append(0);
	        }
	        hexString.append(shaHex);
	      }
	      return hexString.toString();
	    } catch (NoSuchAlgorithmException e) {
	      logger.error(e.getMessage(), e);
	    }

	    return "";
	  }

	  public static String SHA1(String input)
	  {
	    try
	    {
	      MessageDigest digest = MessageDigest.getInstance("SHA-1");
	      digest.update(input.getBytes());
	      byte[] messageDigest = digest.digest();

	      StringBuffer hexString = new StringBuffer();

	      for (int i = 0; i < messageDigest.length; ++i) {
	        String shaHex = Integer.toHexString(messageDigest[i] & 0xFF);
	        if (shaHex.length() < 2) {
	          hexString.append(0);
	        }
	        hexString.append(shaHex);
	      }
	      return hexString.toString();
	    }
	    catch (NoSuchAlgorithmException e) {
	      logger.error(e.getMessage(), e);
	    }

	    return "";
	  }

	  public static byte[] HmacSHA1Encrypt(String encryptText, String encryptKey)
	    throws Exception
	  {
	    byte[] data = encryptKey.getBytes("UTF-8");

	    SecretKey secretKey = new SecretKeySpec(data, "HmacSHA1");

	    Mac mac = Mac.getInstance("HmacSHA1");

	    mac.init(secretKey);

	    byte[] text = encryptText.getBytes("UTF-8");

	    return mac.doFinal(text);
	  }

	  private static String byte2hex(byte[] bytes) {
	    StringBuilder sign = new StringBuilder();
	    for (int i = 0; i < bytes.length; ++i) {
	      String hex = Integer.toHexString(bytes[i] & 0xFF);
	      if (hex.length() == 1) {
	        sign.append("0");
	      }
	      sign.append(hex.toUpperCase());
	    }
	    return sign.toString();
	  }

	  private static byte[] encryptHMAC(String data) throws IOException {
	    byte[] bytes = null;
	    try {
	      MessageDigest md = MessageDigest.getInstance("SHA-1");
	      bytes = md.digest(data.getBytes("UTF-8"));
	    } catch (GeneralSecurityException gse) {
	      throw new IOException(gse);
	    }
	    return bytes;
	  }

	  public static void main(String[] agrs) {
	  	logger.debug("sdjfielasfjeisjf");
	    String str = "CODE=COM.XINIU.ERP&NAME=犀牛ERP&ISV_ID=1";
	    str = str.toUpperCase();
	    String key = MD5(str);
	    System.out.println(key);

	    str = new StringBuilder().append(str).append("&KEY=").append(key).toString();
	    str = str.toUpperCase();
	    System.out.println(str);

	    String secret = MD5(str);
	    System.out.println(secret);
	  }
}
