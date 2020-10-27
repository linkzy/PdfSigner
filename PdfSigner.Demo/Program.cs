using System;
using System.IO;

namespace PdfSigner.Demo
{
    class Program
    {
        static void Main(string[] args)
        {
            // Load pdf and certificate
            byte[] pdfToSign = File.ReadAllBytes(Directory.GetCurrentDirectory() + @"\\Content\TestDocument.pdf");
            byte[] certificateToUse = File.ReadAllBytes(Directory.GetCurrentDirectory() + @"\\Content\TestCertificate.pfx");

            // Set text and image to show at the bottom of each page
            var textToShow = String.Format("Signed by: MySelf!!\nSign date: {0}", DateTime.Now.ToShortDateString());            
            var imageToShow = "https://i.ibb.co/YkPSv3P/dummysing.png";

            // Sign the pdf
            PdfSigner signer = new PdfSigner();
            var signedDocumentWithImage = signer.Sign(pdfToSign, certificateToUse, "", textToShow, imageToShow);

            // Save the signed pdf
            File.WriteAllBytes(Directory.GetCurrentDirectory() + @"\\Signed.pdf", signedDocumentWithImage);

            Console.WriteLine("Check your signed document at: " + Directory.GetCurrentDirectory());
        }
    }
}
