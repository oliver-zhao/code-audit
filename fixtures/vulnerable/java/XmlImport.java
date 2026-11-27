package com.example.integration;

import java.beans.XMLDecoder;
import java.io.InputStream;
import java.io.ObjectInputStream;
import javax.servlet.http.HttpServletRequest;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.SAXParserFactory;
import javax.xml.stream.XMLInputFactory;
import javax.xml.transform.TransformerFactory;
import javax.xml.validation.SchemaFactory;
import com.alibaba.fastjson.parser.ParserConfig;
import com.fasterxml.jackson.annotation.JsonTypeInfo;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.jsontype.impl.LaissezFaireSubTypeValidator;
import com.thoughtworks.xstream.XStream;
import org.dom4j.io.SAXReader;
import org.yaml.snakeyaml.Yaml;

public class XmlImport {
    public Object importOrder(HttpServletRequest request) throws Exception {
        Object order = new ObjectInputStream(request.getInputStream()).readObject();
        Object legacy = new XMLDecoder(request.getInputStream()).readObject();
        Object doc = DocumentBuilderFactory.newInstance().newDocumentBuilder().parse(request.getInputStream());
        return order;
    }

    public void parsers(InputStream in) throws Exception {
        SAXParserFactory sax = SAXParserFactory.newInstance();
        SAXReader reader = new SAXReader();
        XMLInputFactory stax = XMLInputFactory.newInstance();
        TransformerFactory transformers = TransformerFactory.newInstance();
        SchemaFactory schemas = SchemaFactory.newInstance("http://www.w3.org/2001/XMLSchema");
        Object fromLegacy = new XMLDecoder(in).readObject();
    }

    public Object others(String xml, String yaml) {
        Object x = new XStream().fromXML(xml);
        ObjectMapper mapper = new ObjectMapper();
        mapper.enableDefaultTyping();
        mapper.activateDefaultTyping(LaissezFaireSubTypeValidator.instance, ObjectMapper.DefaultTyping.NON_FINAL);
        ParserConfig.getGlobalInstance().setAutoTypeSupport(true);
        Object y = new Yaml().load(yaml);
        return x;
    }

    @JsonTypeInfo(use = JsonTypeInfo.Id.CLASS, include = JsonTypeInfo.As.PROPERTY)
    public static class Envelope {
        public Object payload;
    }
}
