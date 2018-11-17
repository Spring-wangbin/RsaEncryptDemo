package demo;

import util.EncryptUtil;
import util.RsaEncryptUtil;

import java.util.UUID;

public class Demo {

	public static void main(String[] args) throws Exception {
		/**
		 * 注册操作，密码加密保存流程
		 * 0.app端输入用户密码，
		 * 0-1 app端将密码加密，调用pc端接口登录(私钥加密)
		 * 0-2 pc端接受到信息，对密码进行解密（公钥解密）
		 * 1.UUID生成密码盐值，并保存
		 * 2.通过原密码与盐值，调用加密算法（放牛娃加密算法），对密码进行加密保存
		 * 
		 */
		String realPwd = "qwer1234";
		realPwd = RsaEncryptUtil.encryptByPrivateKey(realPwd);
		realPwd = RsaEncryptUtil.decryptByPublicKey(realPwd);
		
		String salt = UUID.randomUUID().toString();
		String pass = EncryptUtil.SHA1(EncryptUtil.MD5(realPwd) + salt);
		System.out.println("保存的密码：pass:"+pass+"--salt:"+salt);
		
		/**
		 * 登录操作，密码处理流程
		 * 1.app端输入用户密码
		 * 2.app端将密码加密，调用pc端接口登录(私钥加密)
		 * 3.pc端接受到信息，对密码进行解密（公钥解密）
		 * 4.通过数据库中保存的加密密码与盐值对原密码进行校验
		 */
		String logPwd = realPwd;
		logPwd = RsaEncryptUtil.encryptByPrivateKey(logPwd);
		System.out.println(logPwd);
		logPwd = RsaEncryptUtil.decryptByPublicKey(logPwd);
		System.out.println(logPwd);
		
		//登录密码校验
		String realPass = realPwd;
		String dbPass = pass;
		
		boolean aaa = dbPass.equals(EncryptUtil.SHA1(EncryptUtil.MD5(realPass)+salt));
		System.out.println(aaa);
	}
}
