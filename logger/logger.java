/** Switch Log paser
 * @author Jacksieen
 * Date Jul 2 17:20 CST 2014
 */


import java.io.*;
import java.util.*;
import java.util.regex.*;
import java.text.*;

public class logger{
    public static void main(String[] args) throws IOException{
        File f = new File("/tmp/log/remotelog");
        Scanner in = new Scanner(f);
        while (in.hasNextLine()){
            String text=in.nextLine();
            parsing(text);
        }
        FileWriter fw = new FileWriter(f);
        fw.write("");
        fw.close();
    }
    static void parsing(String log){
        /* regex to split messages */
        String reg = "-==-";
        Pattern pat = Pattern.compile(reg);
        String[] ss = pat.split(log);
        if (ss[0].equals("[JP]")){
            JP j = new JP(ss);
            if (j.mailContent != null)
                System.out.println(j.mailContent);
        }
        else if (ss[0].equals("[H3C]")){
            H3C h = new H3C(ss);
            if (h.mailContent != null)
                System.out.println(h.mailContent);
        }
        else if (ss[0].equals("[CS]")){

        }
        else return;
    }
}

class logentry{
    public String tag;
    public Date receiveTime = new Date();
    public Date deviceTime;
    public String host;
    public String facility;
    public String content;
    public String mailContent;
    SimpleDateFormat outDf = new SimpleDateFormat("yyyy/MM/dd HH:mm:ss zzz");

    logentry(String[] logs){       //constructor
        SimpleDateFormat sdf = new SimpleDateFormat("MMM dd HH:mm:ss");
        try{
            deviceTime = sdf.parse(logs[1]);
        }catch (ParseException pe){
            System.out.println(String.format("(can not parsing \"%s\", use the server time instead!)", logs[1]));
            deviceTime = new Date();
        }
        deviceTime.setYear(new Date().getYear());
        host = logs[2];
        facility = logs[3];
        content = logs[4];
        
    }
}

class JP extends logentry{
    public String module;
    public String user;
    public String fromHost;
    public String cmd;
    boolean loginFlag = false;
    JP(String[] logs){
        super(logs); 
        String reg = "%\\S+:";
        Pattern pat = Pattern.compile(reg);
        Matcher mat = pat.matcher(content);
        if (mat.find()){
            module = mat.group();
            content = mat.replaceFirst("");
        }
        if (facility.contains("login") || facility.contains("mgd")){
            parse();
        }
    }

    void parse(){
        Pattern pat;
        Matcher mat;
        if (module.contains("AUTH-5:") && content.contains("attempt")){
            pat = Pattern.compile("user \\w+");
            mat = pat.matcher(content);
            if (mat.find()){
                user = mat.group().replace("user ","");
            }
            pat = Pattern.compile("host \\S+");
            mat = pat.matcher(content);
            if (mat.find()){
                fromHost = mat.group().replace("host ","");
            }
            mailContent = String.format("User %s attempt to login %s from %s, at %s", user, host, fromHost, outDf.format(deviceTime));
        }
        else if (module.contains("AUTH-5") && content.contains("LOGIN FAILURE"))
            mailContent = String.format("%s at %s", content, outDf.format(receiveTime));

        else if (module.contains("UI_LOGIN_EVENT")){
            pat = Pattern.compile("User '\\w+' login");
            mat = pat.matcher(content);
            if (mat.find()){
                loginFlag = true;
            }
        }
        else if (module.contains("UI_CMDLINE_READ_LINE")){
            pat = Pattern.compile("User '\\w+");
            mat = pat.matcher(content);
            if (mat.find())
                user = mat.group().replace("User '", "");
            pat = Pattern.compile("command .+");
            mat = pat.matcher(content);
            if (mat.find()){
                cmd = mat.group().replace("command ", "");
            }
            mailContent = String.format("User %s issued command %s at %s", user, cmd, host);
        } 
    }
}

class H3C extends logentry{
    public String user;
    public String fromHost;
    public String cmd;
    
    H3C(String[] logs){
        super(logs);
        if (facility.contains("SHELL/"))
            parse();
    }
    void parse(){
        Pattern pat;
        Matcher mat;
        if (facility.contains("SHELL_LOGINFAIL")){
            pat = Pattern.compile("TELNET .+");
            mat = pat.matcher(content);
            if (mat.find()){
                mailContent = mat.group().replace("TELNET ","")+"\b at "+outDf.format(deviceTime);
                String tmp = String.format(" login %s ", host);
                mailContent = mailContent.replace(" log in ", tmp);
            }
        }

        else if (facility.contains("SHELL_LOGIN(")){
            pat = Pattern.compile("\\w+ logged in");
            mat = pat.matcher(content);
            if (mat.find())
                user = mat.group().replace(" logged in", "");
            pat = Pattern.compile("from \\S+");
            mat = pat.matcher(content);
            if (mat.find())
                fromHost = mat.group().replace("from ", "");
            mailContent = String.format("User %s attempt to login %s from %s, at %s", user, host, fromHost, outDf.format(deviceTime));
        }

        else if (facility.contains("SHELL_CMD")||facility.contains("SHELL_SECLOG")){
            pat = Pattern.compile("Command is .+");
            mat = pat.matcher(content);
            if (mat.find())
                cmd = mat.group().replace("Command is ","");
            pat = Pattern.compile("-User=.+;");
            mat = pat.matcher(content);
            if (mat.find())
                user = mat.group().replace("-User=","").replace(";","");
            mailContent = String.format("User %s issued command %s at %s", user, cmd, host);
        }
    }
}
