"""附件文件类型与简单危险特征判断。"""

from pathlib import PurePath

DANGEROUS_EXTENSIONS = {
    ".exe",
    ".dll",
    ".scr",
    ".com",
    ".msi",
    ".bat",
    ".cmd",
    ".vbs",
    ".vbe",
    ".js",
    ".jse",
    ".ps1",
    ".hta",
    ".lnk",
}

MACRO_EXTENSIONS = {".docm", ".xlsm", ".pptm"}

ARCHIVE_EXTENSIONS = {".iso", ".img", ".jar"}


def get_extension(filename: str) -> str:
    """获取最后一个扩展名，统一为小写。"""
    return PurePath(filename).suffix.lower()


def is_dangerous_extension(filename: str) -> bool:
    return get_extension(filename) in DANGEROUS_EXTENSIONS


def is_macro_document(filename: str) -> bool:
    return get_extension(filename) in MACRO_EXTENSIONS


def is_archive_or_disk_image(filename: str) -> bool:
    return get_extension(filename) in ARCHIVE_EXTENSIONS


def has_double_extension(filename: str) -> bool:
    """检测类似 invoice.pdf.exe 的双扩展名。"""
    parts = filename.lower().split(".")
    if len(parts) < 3:
        return False
    return f".{parts[-1]}" in DANGEROUS_EXTENSIONS and parts[-2] in {
        "pdf",
        "doc",
        "docx",
        "xls",
        "xlsx",
        "ppt",
        "pptx",
        "txt",
        "jpg",
        "png",
    }


def mime_mismatch(declared_mime: str, detected_mime: str) -> bool:
    """只对当前项目已知的常见文件签名做简单不一致判断。"""
    declared = (declared_mime or "").lower()
    detected = (detected_mime or "").lower()
    if not declared or not detected or detected == "application/octet-stream":
        return False

    if detected == "application/x-dosexec":
        return declared not in {
            "application/x-dosexec",
            "application/octet-stream",
            "application/x-msdownload",
        }
    if detected == "application/pdf":
        return declared != "application/pdf"
    if detected == "application/zip":
        return declared not in {"application/zip", "application/x-zip-compressed"}
    return False
