package com.example.integration;

import java.io.InputStream;
import javax.servlet.http.HttpServletRequest;
import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.SAXParserFactory;
import javax.xml.stream.XMLInputFactory;
import javax.xml.transform.TransformerFactory;
import com.fasterxml.jackson.annotation.JsonSubTypes;
import com.fasterxml.jackson.annotation.JsonTypeInfo;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.jsontype.BasicPolymorphicTypeValidator;
import org.yaml.snakeyaml.LoaderOptions;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.SafeConstructor;

public class XmlImport {
    public Object importOrder(HttpServletRequest request) throws Exception {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        Object doc = dbf.newDocumentBuilder().parse(request.getInputStream());
        Order order = new ObjectMapper().readValue(request.getInputStream(), Order.class);
        return order;
    }

    public void parsers(InputStream in) throws Exception {
        SAXParserFactory sax = SAXParserFactory.newInstance();
        sax.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        XMLInputFactory stax = XMLInputFactory.newInstance();
        stax.setProperty(XMLInputFactory.SUPPORT_DTD, false);
        TransformerFactory transformers = TransformerFactory.newInstance();
        transformers.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
    }

    public Object others(String yaml) {
        ObjectMapper mapper = new ObjectMapper();
        mapper.activateDefaultTyping(BasicPolymorphicTypeValidator.builder().allowIfSubType(Order.class).build());
        Object y = new Yaml(new SafeConstructor(new LoaderOptions())).load(yaml);
        return y;
    }

    @JsonTypeInfo(use = JsonTypeInfo.Id.NAME, include = JsonTypeInfo.As.PROPERTY)
    @JsonSubTypes({@JsonSubTypes.Type(value = Order.class, name = "order")})
    public static class Order {
        public String id;
    }
}
