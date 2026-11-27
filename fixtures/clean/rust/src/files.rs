// Containment-checked paths and archive extraction.
use actix_web::{get, web, HttpResponse};
use std::fs::{self, File};
use std::io;
use std::path::{Component, Path};

#[get("/download/{name}")]
pub async fn download(name: web::Path<String>) -> HttpResponse {
    let name = name.into_inner();
    if Path::new(&name).components().any(|c| !matches!(c, Component::Normal(_))) {
        return HttpResponse::BadRequest().finish();
    }
    let data = fs::read(Path::new("/srv/files").join(&name)).unwrap_or_default();
    HttpResponse::Ok().body(data)
}

pub fn extract_zip(reader: File, dest: &Path) -> io::Result<()> {
    let mut archive = zip::ZipArchive::new(reader)?;
    for i in 0..archive.len() {
        let mut file = archive.by_index(i)?;
        let Some(relative) = file.enclosed_name() else { continue };
        let mut out = File::create(dest.join(relative))?;
        io::copy(&mut file, &mut out)?;
    }
    Ok(())
}

pub fn extract_tar(reader: File, dest: &Path) -> io::Result<()> {
    let mut archive = tar::Archive::new(reader);
    for entry in archive.entries()? {
        let mut entry = entry?;
        entry.unpack_in(dest)?;
    }
    Ok(())
}
