package speck;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Base64;

public class SPECK {
static String plainText="plain_text";
static String password="passwordf";

public  static byte[] circularBitShiftingRight(byte[] target,int amount){
    byte[] result=new byte[target.length];
    byte w;
    String gw=toBinery(target);
    String g=gw.substring(gw.length()-amount, gw.length())+gw.substring(0,gw.length()-amount);
    for(int i=0;i<target.length;i++){
        String q=g.substring(i*8,i*8+8);
        w=(byte)Integer.parseInt(q,2);
        result[i]=w;
    }
    return result;
}
private static String toBinery(byte[] target){
    int a;
    StringBuilder sb=new StringBuilder();
    for(int i=0;i<target.length;i++){
        a=target[i];
        for(int j=7;j>=0;j--)
            sb.append((a >> j )& 1);
    }
    return sb.toString();
}
public static byte[] circularBitShiftingLeft(byte[] target,int amount){
    byte[] result=new byte[target.length];
      byte w;
    String gw=toBinery(target);
    String g=gw.substring(amount, gw.length())+gw.substring(0,amount);
    for(int i=0;i<target.length;i++){
        String q=g.substring(i*8,i*8+8);
        w=(byte)Integer.parseInt(q,2);
        result[i]=w;
    }
    return result;
}
public static byte rotateLeft(byte number, int amount) {
   return (byte) (number << amount | number >>> (8-amount));
}
public static byte rotateRight(byte number, int amount) {
   return (byte) (number >>> amount | number << (8-amount));
}
public static byte[] plus(byte[] a,byte[] b){
   byte[] s=new byte[8];
   for(int i=0;i<8;i++){
       s[i]=(byte) (a[i]+b[i]);
   }
   return s;
}
//------------------------------------------------------------------------
public static byte[] generateKey(byte[] k1,byte[] k2,int x){
    byte[] a=circularBitShiftingRight(k1,8);
    a=plus(a,k2);
    for(int i=0;i<8;i++)
        a[i]=(byte) (a[i]^x);
    return a;
}
public static byte[] generatekey2(byte[] k1,byte[] k2){
     byte[] t =circularBitShiftingLeft(k2,3);    
      for(int i=0;i<8;i++)
        t[i]=(byte) (t[i]^k1[i]);
      return t;
}
//========================================================================
public static void SpeckDec(byte[] sha,String base64message){
    byte[] decodedString = Base64.getDecoder().decode(base64message.getBytes());
    byte[] data=new byte[decodedString.length];
    byte[] keys=new byte[256];
    byte[] key=new byte[16];
    byte[] pofd;
    final int tool=decodedString.length/16;
    for(int I = 0; I < 16; I++)
        key[I] = (byte) (sha[I] ^ sha[I + 16]);
        
    byte[] k1 = Arrays.copyOfRange(key, 0, 8);
    byte[] k2 = Arrays.copyOfRange(key, 8, 16);
    for (int i=0;i<32;i++)
    {
        k1=generateKey(k1,k2,i);
        k2=generatekey2(k1,k2);
        System.arraycopy(k2,0,keys,i*8,8);
    }    
    for(int i=0;i<tool ;i++){
        pofd=Arrays.copyOfRange(decodedString,i*16,i*16+16);
        pofd=dec(pofd,keys);
        System.arraycopy(pofd, 0, data, i*16, 16);
    }
    System.out.print(new String(data).trim());
}
//-----------------------------------------------------------------------
public static byte[] dec(byte[] pieceofdata,byte[] keys){
    byte[] result=new byte[16];
    byte[] key;
    byte[] ct1,ct2;
    int m;
    ct1=Arrays.copyOfRange(pieceofdata, 0, 8);
    ct2=Arrays.copyOfRange(pieceofdata, 8, 16);
    for(int i=0;i<32;i++){
        m=256-((i+1)*8);
          key=Arrays.copyOfRange(keys,m,m+8);
        for(int j=0;j<8;j++)
            ct2[j]=(byte) (ct1[j]^ct2[j]);
        ct2=circularBitShiftingRight(ct2,3);
        for(int j=0;j<8;j++)
            ct1[j]=(byte) (ct1[j]^key[j]);
        for(int j=0;j<8;j++)
            ct1[j]=(byte) (ct1[j]-ct2[j]);
        ct1=circularBitShiftingLeft(ct1,8); 
    }   
    System.arraycopy(ct1, 0, result, 0, 8);
    System.arraycopy(ct2, 0, result, 8, 8);
    return result;
}
//------------------------------------------------------------------------
public static void SpeckEnc(byte[] sha,String message){
    byte[] data=message.getBytes();
    byte[] newdata;
    byte[] lastblock=new byte[16];
    byte[] key=new byte[16];
    int tool=data.length/16;
    final int baghi=data.length%16;
    final int T=32;
    for(int I = 0; I < 16; I++)
        key[I] = (byte) (sha[I] ^ sha[I + 16]);
    if(baghi!=0){
        int toollast=data.length - tool*16;
        for(int ba=0;ba<16;ba++){
            if(ba<toollast)
                lastblock[ba]=data[tool*16+ba];
            else
                lastblock[ba]=0;
            }
        tool++;
        newdata=new byte[tool*16];
        System.arraycopy(data,0,newdata,0,(tool-1)*16);
        System.arraycopy(lastblock,0,newdata,(tool-1)*16,16);
    }else
        newdata=data;
   
    byte[] c=new byte[newdata.length];
    byte[] k1 = Arrays.copyOfRange(key, 0, 8);
    byte[] k2 = Arrays.copyOfRange(key, 8, 16);
    byte[] pofd;
    for(int i=0;i<tool;i++){
        pofd=Arrays.copyOfRange(newdata,i*16,i*16+16);
        pofd=enc(pofd,k1,k2);
        System.arraycopy( pofd,0,c,i*16,16);
    }
    String encoded = Base64.getEncoder().encodeToString(c);
    System.out.println(" encrypted ====>"+encoded+"\n    plain ====>"+Base64.getEncoder().encodeToString(plainText.getBytes()));
    SpeckDec(sha,encoded);

 }
public static byte[] enc(byte[] piecedata,byte[] k1,byte[] k2){
    byte[] result=new byte[16];
    byte[] pt1,pt2;
    pt1=Arrays.copyOfRange(piecedata, 0, 8);
    pt2=Arrays.copyOfRange(piecedata, 8, 16);
    for(int si = 0; si < 32; si++) {
         k1=generateKey(k1,k2,si);
         k2=generatekey2(k1,k2);
        pt1=circularBitShiftingRight(pt1,8);
        pt1=plus(pt1,pt2);
        for(int i=0;i<8;i++)
            pt1[i]=(byte) (pt1[i]^k2[i]);
        pt2=circularBitShiftingLeft(pt2,3);
        for(int i=0;i<8;i++)
            pt2[i]=(byte) (pt1[i]^pt2[i]);
       }    
    System.arraycopy(pt1,0,result,0,8);
    System.arraycopy(pt2,0,result,8,8);
    return result;
    } 
    //----------------------------------------------------------------
    private static String bytesToHex(byte[] hash) {
    StringBuilder hexString = new StringBuilder();
    for (int i = 0; i < hash.length; i++) {
    String hex = Integer.toHexString(0xff & hash[i]);
    if(hex.length() == 1) hexString.append('0');
        hexString.append(hex);
    }
    return hexString.toString();
}
///----------------------------------------------
public static void main(String[] args) throws NoSuchAlgorithmException {
    MessageDigest digest = MessageDigest.getInstance("SHA-256");
    byte[] encodedhash = digest.digest(password.getBytes());  
    SpeckEnc(encodedhash,plainText);
       }
}
