package com.example.servingwebcontent.demo;

import java.util.regex.Pattern;
import java.util.HashMap;
import java.util.regex.Matcher;

public class Utilities {
    public static HashMap<String, String> parseCertSubjectDN(String subString)
    {
        Pattern p = Pattern.compile("CN=(.*),O=(.*),C=(.*),L=(.*),ST=(.*)");
        Matcher m = p.matcher(subString);
        HashMap<String, String> retval = new HashMap<String,String>();
        if(m.matches())
        {
            retval.put("CN", m.group(1));
            retval.put("O", m.group(2));
            retval.put("C", m.group(3));
            retval.put("L", m.group(4));
            retval.put("ST", m.group(5));
            return retval;
        }
        else
        {
            return retval;
        }
    }    
}