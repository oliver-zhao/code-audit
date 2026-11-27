package com.example.web;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.UUID;
import org.apache.commons.io.FilenameUtils;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.multipart.MultipartFile;

@Controller
public class UploadController {
    private final Path uploads = Paths.get("/srv/uploads");

    @PostMapping("/upload")
    public String upload(@RequestParam("file") MultipartFile file) throws Exception {
        String extension = FilenameUtils.getExtension(FilenameUtils.getName(file.getOriginalFilename()));
        file.transferTo(uploads.resolve(UUID.randomUUID() + "." + extension));
        return "redirect:/files";
    }

    @GetMapping("/orders/{id}/done")
    public String done(@RequestParam("id") long id) {
        return "redirect:/orders/" + id;
    }
}
