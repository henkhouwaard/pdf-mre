using System.Reflection;
using iText.Bouncycastle.Crypto;
using iText.Bouncycastle.X509;
using iText.Commons.Bouncycastle.Cert;
using iText.Html2pdf;
using iText.Kernel.Geom;
using iText.Kernel.Pdf;
using iText.Layout.Font;
using iText.Signatures;
using Org.BouncyCastle.Pkcs;
using Path = System.IO.Path;

public static class PdfService
{
    private static readonly string ResourcesPath =
        Path.GetDirectoryName(Assembly.GetAssembly(typeof(PdfService))!.Location)!;

    private static readonly string Pkcs12File = Path.Combine(ResourcesPath, "henkselfsigned.p12");
    private static readonly string FreeSansTtf = Path.Combine(ResourcesPath, "FreeSans.ttf");
    private const string Pkcs12Password = "henk";

    private const string Html = """
                                <!DOCTYPE html>
                                <html lang="en">
                                <head>
                                    <meta charset="utf-8" />
                                    <title>UA compliant</title>
                                    <style>
                                        @font-face {
                                            font-family: MyCustomFont;
                                            src: url('./FreeSans.ttf') format('truetype');
                                        }
                                        body {
                                            font-family: MyCustomFont, Arial, sans-serif;
                                            font-size: 1em;
                                        }
                                        .aclassname {
                                            color: #233983;
                                            font-size: 20px;
                                            margin-bottom: 2em;
                                        }
                                    </style>
                                </head>

                                <body>
                                <div class="aclassname">This should be UA compliant</div>
                                </body>
                                </html>
                                """;


    public static void GenereerPdf()
    {
        using var unsignedWriteStream = new FileStream(Path.Combine(ResourcesPath, "unsigned.pdf"), FileMode.Create);
        using var writer = new PdfWriter(unsignedWriteStream,
            new WriterProperties().AddUAXmpMetadata().SetPdfVersion(PdfVersion.PDF_1_7));
        using var pdfDoc = new PdfDocument(writer);
        using var writeStream = new MemoryStream();
        {
            pdfDoc.SetTagged();
            pdfDoc.GetCatalog()
                .SetViewerPreferences(new PdfViewerPreferences().SetDisplayDocTitle(true));

            var properties = new ConverterProperties();
            properties.SetFontProvider(new FontProvider());
            properties.GetFontProvider().AddFont(FreeSansTtf);
            HtmlConverter.ConvertToPdf(Html, pdfDoc, properties);

            // regel cryptografie
            var store = new Pkcs12StoreBuilder().Build();
            using (var fs = new FileStream(Pkcs12File, FileMode.Open))
            {
                store.Load(fs, Pkcs12Password.ToCharArray());
            }

            string alias = null;
            foreach (var al in store.Aliases)
            {
                alias = al;
                break;
            }

            var pk = store.GetKey(alias).Key;
            X509CertificateEntry[] ce = store.GetCertificateChain(alias);
            var chain = new IX509Certificate[ce.Length];
            for (var k = 0; k < ce.Length; ++k) chain[k] = new X509CertificateBC(ce[k].Certificate);

            // maak signature object
            IExternalSignature pks = new PrivateKeySignature(new PrivateKeyBC(pk), DigestAlgorithms.SHA256);

            // onderteken document
            using var signingFileReader = new FileStream(Path.Combine(ResourcesPath, "signed.pdf"), FileMode.Open);
            using var signingReader = new PdfReader(signingFileReader);
            var signer = new PdfSigner(signingReader, writeStream, new StampingProperties().UseAppendMode());
            signer.SetLocation("Earth");
            signer.SetReason("I am the author of this document");
            signer.SetPageNumber(signer.GetDocument().GetNumberOfPages());
            signer.SetPageRect(new Rectangle(0, 0, 200, 100));
            signer.SetFieldName("Signature");
            signer.GetSignatureField().SetAlternativeName("Signature");
            signer.SetCertificationLevel(PdfSigner.CERTIFIED_FORM_FILLING_AND_ANNOTATIONS);
            signer.SignDetached(pks, chain, null, null, null, 0, PdfSigner.CryptoStandard.CMS);
        }
    }
}