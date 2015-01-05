<?php
/**
 * 迷你云PHP-SDK
 * 适用迷你云1.5版本
 */
class MiniSDK15{	
	//appKey，由管理事先分配好
	private $appKey="d6n6Hy8CtSFEVqNh";
	//appSecret，由管理事先分配好
	private $appSecret="e6yvZuKEBZQe9TdA"; 
	//accessToken，访问token，由用户账户+密码换取获得的
	private $accessToken;
	//迷你云服务器Host
	private $host; 
	/**
	 * 构造函数
	 */
	public function MiniSDK15($host){
		$this->host = $host;
	}
	/**
	 * 登陆接口 
	 */
	public function login($userName,$userPassword){
		$url = $this->host."/api.php/1/oauth2/token";   
		$data = array(
					'username'=>$userName,
					'password'=>$this->encryPassword($userPassword),
					'device_type'=>2,
					'device_name'=>"thrid",
					'device_info'=>$userName."thrid",
					'grant_type'=>"password",
					'client_id'=>$this->appKey,
					'client_secret'=>$this->appSecret,
				); 		
		$result = json_decode($this->request($url,$data));		
		$this->accessToken = $result->{"access_token"}; 
		return $result;
	}
	/**
	 * 文件列表
	 */
	public function listFile($path){
		if(empty($path)){
			$path = "/";
		} 
		$url = $this->host."/api.php/1/metadata/miniyun".urlencode($path);
		$data = array();
		$data = $this->signUrl2Paramters($url,$data);  		
		$result = json_decode($this->request($url,$data));
		return $result;
	}
	/**
	 * 获得用户信息
	 */
	public function accountInfo(){ 
		$url = $this->host."/api.php/1/account/info";
		$data = array();
		$data = $this->signUrl2Paramters($url,$data);  		
		$result = json_decode($this->request($url,$data));
		return $result;
	}
	/**
	 * 获得用户信息
	 */
	public function createFolder($path){ 
		$url = $this->host."/api.php/1/fileops/create_folder";
		$data = array(
			"root"=>"miniyun",
			"path"=>$path,	 
			);
		$data = $this->signUrl2Paramters($url,$data);  		
		$result = json_decode($this->request($url,$data));
		return $result;
	}
	/**
	 * 修改名称,适合文件夹/文件，下面2个参数都要绝对路径
	 */
	public function rename($path,$newPath){ 
		$url = $this->host."/api.php/1/fileops/move";
		$data = array(
			"root"=>"miniyun",
			"from_path"=>$path,	
			"to_path"=>$newPath, 
			);
		$data = $this->signUrl2Paramters($url,$data);  		
		$result = json_decode($this->request($url,$data));
		return $result;
	}
	/**
	 * 修改名称,适合文件夹/文件，下面2个参数都要绝对路径
	 */
	public function delete($path){ 
		$url = $this->host."/api.php/1/fileops/delete";
		$data = array(
			"root"=>"miniyun",
			"path"=>$path,	 
			);
		$data = $this->signUrl2Paramters($url,$data);  		
		$result = json_decode($this->request($url,$data));
		return $result;
	}
	/**
	 * 创建外链，适合文件夹/文件
	 */
	public function createLink($path){ 
		$url = $this->host."/api.php/1/link/create".urlencode($path);
		$data = array(
			"root"=>"miniyun", 
			); 
		$data = $this->signUrl2Paramters($url,$data);  		
		$result = json_decode($this->request($url,$data));
		return $result;
	}
	
	/**
	 * 对url签名
	 */
	private function signUrl2Paramters($url,$params){		
	    //要把$url里面的%2f替换为/
		$url = str_replace("%2F", "/", $url);
		$url = str_replace("%2f", "/", $url); 
		$info = parse_url($url);
		$host = $info["host"];
		if(!array_key_exists("port",$info)){
			$port = 80;
		}else{			
			$port = $info["port"];
		}
		$path = $info["path"];
		$str = $host.":".$port.$path."?access_token=".$this->accessToken."&client_id=".$this->appKey."&client_secret=".$this->appSecret;   
		$signCode = md5($str);
		$params["access_token"] = $this->accessToken;
		$params["sign"] = $signCode;
		return $params;
	}
	/**
	*发送请求，迷你云接收POST请求
	*/
	private function request($url,$params){
		$data = "";
		foreach($params as $key=>$value) { $data .= $key.'='.$value.'&'; }
		rtrim($data,'&'); 
		$ch = curl_init(); 
		curl_setopt($ch,CURLOPT_URL,$url);
		curl_setopt($ch, CURLOPT_HEADER, 0); 
		curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);  
		curl_setopt($ch,CURLOPT_POST,count($params));
		curl_setopt($ch,CURLOPT_POSTFIELDS,$data); 
		$data = curl_exec($ch);
		curl_close($ch);   
		return $data;
	}
	/**
	*对密码DES加密
	*DES密钥是appKey的前8位字符串，密文使用base64编码后转换为大写的16进制字符串即可
	*/
	private function encryPassword($password){
		include "./Crypt_DES.php";
        //DES加密算法是标准的，其他开发语言的DES加密都可以		
		$key  = substr($this->appKey, 0, 8); 
		$cryptDes = new Crypt_DES();
        $cryptDes->setKey($key);
        $cryptDes->setIV($key);
        $encrypted =$cryptDes->encrypt($password);
		//base64编码
        $base64Code = base64_encode($encrypted); 
		//转换为16进制大写字符串
		$hex="";
        for   ($i=0;$i<strlen($base64Code);$i++)
        $hex.=dechex(ord($base64Code[$i]));
        $hex=strtoupper($hex);
		return $hex;
	}
}
//迷你云服务器地址
$host = "http://yp.nje.cn";
//用户名
$userName = "jktest1";
//用户密码
$userPassword = "jktest@1";
$miniSDK = new MiniSDK15($host);
$data = $miniSDK->login($userName,$userPassword); 
print_r($data);
//文件列表
$data = $miniSDK->listFile("/");
print_r($data);
//获得用户信息
//$data = $miniSDK->accountInfo();
//print_r($data);
//创建目录
//$data = $miniSDK->createFolder("/测试1/测试2/测试31");
//print_r($data);
//修改名称
//$data = $miniSDK->rename("/测试1/测试2/测试3","/测试1/测试2/测试4");
//print_r($data);
//修改名称
//$data = $miniSDK->delete("/测试1/测试2/测试4");
//print_r($data);
//创建外链
$data = $miniSDK->createLink("/测试1/测试2");
print_r($data);