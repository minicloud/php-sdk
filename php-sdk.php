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
	 * 创建文件
	 */
	public function createFile($localPath,$remotePath){ 
		$siteInfo = $this->siteInfo();
		if(array_key_exists("dataMode",$siteInfo)){
			$dataMode = $siteInfo->{"dataMode"}; 
			if($dataMode->{"source"}==="miniStor"){
				//启用迷你存储
			    $data = $this->miniStoreSec($localPath,$remotePath); 
				//如果返回值uri属性标记该文件上传的迷你存储的地址,说明该文件需要上传
				//如果没有uri,否则标记文件已经上传成功了
				if(array_key_exists("uri",$data)){
					//该文件需要上传
					//与文件二进制内容一并提交的，还有秒传接口返回的reqeust子对象，将其序列化到url地址
					//从秒传接口返回的uri作为迷你存储的入口地址
					$url    = $data->{"uri"}."?";
					$params = $data->{"request"};
					foreach($params as $key=>$value) { $url .= $key.'='.$value.'&'; }  
					include "./HttpClient.php";
					$http = new HttpClient(); 
					$files = array( 
						'files'=>$localPath,//文件的头标记是files
					); 
					$http->post($url,array(),$files); //提交文件内容的时候，网络不稳定可能会出现错误，通过返回值进行处理
					return json_decode($http->get_body());
				}else{
					return $data;//该文件秒传成功
				}
				
			} 
		}				 
	}
	/**
	 * 获得迷你云站点信息
	 */
	public function siteInfo(){
		$url = $this->host."/api.php/1/info";
		$data = array(  
			);  		
		$result = json_decode($this->request($url,$data));
		return $result;
	}
	/**
	 * 迷你存储秒传接口
	 * 如果服务器已经存储有该文件内容，则直接成功
	 * 如果服务器没有存储文件内容，在返回迷你存储服务器地址
	 */
	public function miniStoreSec($localPath,$remotePath){
		$hashCode = $this->hashFile($localPath); 
		$fileSize = filesize($localPath);
		
		$url = $this->host."/api.php/1/paramsdata/miniyun".urlencode($remotePath);
		$data = array( 
			"path"=>$remotePath,
			"hash"=>$hashCode,
			"size"=>$fileSize,
			"offset"=>0,
			"overwrite"=>true,
			"parent_rev"=>0,
			"locale"=>"en",
			);
		$data = $this->signUrl2Paramters($url,$data);
		$result = $this->request($url,$data);
		//如果返回值不是false，标示该文件已经上传成功
		if($result!==false){
			$data = json_decode($result); 
			return $data;
		}
		//如果返回值不是false
		return false;
	}
	/**
	 * 计算文件内容的hash值
	 */
	private function hashFile($localPath){
		return sha1_file($localPath);
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
	*根据response的status code，如果执行错误，返回的不是200
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
		$info = curl_getinfo($ch);		
		if($info['http_code'] != 200){
			$output = "No cURL data returned for $url [". $info['http_code']. "]";
			if (curl_error($ch)){
				$output .= "\n". curl_error($ch);
			}
			print_r($output);
			
		    curl_close($ch);   
			return false;
		}else{			
		    curl_close($ch);   
		    return $data;
		} 
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
//$data = $miniSDK->listFile("/");
//print_r($data);
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
//$data = $miniSDK->createLink("/测试1/测试2");
//print_r($data);
//获得迷你云站点信息
//$data = $miniSDK->siteInfo();
//print_r($data);
//上传文件
//请注意，第二个参数是迷你云服务器绝对路径
//$data = $miniSDK->createFile("c:/test.txt","/测试1/test3.txt");
//print_r($data);