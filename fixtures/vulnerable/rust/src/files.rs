// Request values in file paths, Zip Slip and tar slip.
use actix_web::{get, web, HttpResponse};
use std::fs::{self, File};
use std::io;
use std::path::{Path, PathBuf};

#[get("/download/{name}")]
pub async fn download(path: web::Path<String>) -> HttpResponse {
    let data = fs::read(Path::new("/srv/files").join(path.into_inner())).unwrap_or_default();
    HttpResponse::Ok().body(data)
}

pub fn extract_zip(reader: File, dest: &Path) -> io::Result<()> {
    let mut archive = zip::ZipArchive::new(reader)?;
    for i in 0..archive.len() {
        let mut file = archive.by_index(i)?;
        let outpath = dest.join(file.name());
        let mut out = File::create(&outpath)?;
        io::copy(&mut file, &mut out)?;
    }
    Ok(())
}

pub fn extract_tar(reader: File, dest: &Path) -> io::Result<()> {
    let mut archive = tar::Archive::new(reader);
    for entry in archive.entries()? {
        let mut entry = entry?;
        let target: PathBuf = dest.join(entry.path()?);
        entry.unpack(&target)?;
    }
    Ok(())
}
