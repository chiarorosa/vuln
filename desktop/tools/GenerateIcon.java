import java.io.*;
import java.nio.*;
import java.nio.file.*;
import javax.imageio.ImageIO;
public class GenerateIcon {
    public static void main(String[] args)throws Exception{Path dir=Path.of(args[0]);Files.createDirectories(dir);ByteArrayOutputStream png=new ByteArrayOutputStream();ImageIO.write(VulnTheme.icon(256),"png",png);byte[] bytes=png.toByteArray();Files.write(dir.resolve("vuln.png"),bytes);ByteBuffer ico=ByteBuffer.allocate(22+bytes.length).order(ByteOrder.LITTLE_ENDIAN);ico.putShort((short)0).putShort((short)1).putShort((short)1);ico.put((byte)0).put((byte)0).put((byte)0).put((byte)0).putShort((short)1).putShort((short)32).putInt(bytes.length).putInt(22).put(bytes);Files.write(dir.resolve("vuln.ico"),ico.array());}
}
