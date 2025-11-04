package edu.sjsu.cmpe.secainw.service;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Optional;
import java.util.UUID;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import com.itextpdf.kernel.colors.ColorConstants;
import com.itextpdf.kernel.font.PdfFont;
import com.itextpdf.kernel.font.PdfFontFactory;
import com.itextpdf.kernel.pdf.PdfDocument;
import com.itextpdf.kernel.pdf.PdfWriter;
import com.itextpdf.layout.Document;
import com.itextpdf.layout.element.Cell;
import com.itextpdf.layout.element.Paragraph;
import com.itextpdf.layout.element.Table;
import com.itextpdf.layout.properties.TextAlignment;
import com.itextpdf.layout.properties.UnitValue;

import edu.sjsu.cmpe.secainw.model.AnomalyEvent;
import edu.sjsu.cmpe.secainw.repository.AnomalyEventRepository;
import software.amazon.awssdk.core.sync.RequestBody;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;
import software.amazon.awssdk.services.s3.model.PutObjectResponse;

@Service
public class ReportService {
    private static final Logger logger = LoggerFactory.getLogger(ReportService.class);

    @Autowired
    private AnomalyEventRepository anomalyEventRepository;

    @Value("${aws.s3.bucket-name}")
    private String bucketName;

    @Value("${aws.s3.region}")
    private String region;

    private final S3Client s3Client;

    public ReportService() {
        this.s3Client = S3Client.builder()
                .region(Region.of("us-west-2"))
                .build();
    }

    public String generateAndUploadReport(Long eventId) {
        try {
            Optional<AnomalyEvent> eventOpt = anomalyEventRepository.findById(eventId);
            if (eventOpt.isEmpty()) {
                throw new RuntimeException("Anomaly event not found with ID: " + eventId);
            }

            AnomalyEvent event = eventOpt.get();
            
            // Check if a report URL already exists and is not an empty string.
            if (event.getReportUrl() != null && !event.getReportUrl().isEmpty()) {
                logger.info("Report already exists for event {}. Returning existing URL: {}", eventId, event.getReportUrl());
                return event.getReportUrl();
            }

            logger.info("No existing report found for event {}. Generating a new one.", eventId);
            
            byte[] pdfBytes = generatePdfReport(event);
            String reportUrl = uploadToS3(pdfBytes, event);
            
            // Update the event with the report URL
            event.setReportUrl(reportUrl);
            anomalyEventRepository.save(event);
            
            return reportUrl;
        } catch (Exception e) {
            logger.error("Error generating and uploading report for event {}: {}", eventId, e.getMessage(), e);
            throw new RuntimeException("Failed to generate report: " + e.getMessage());
        }
    }

    private byte[] generatePdfReport(AnomalyEvent event) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        PdfWriter writer = new PdfWriter(baos);
        PdfDocument pdfDoc = new PdfDocument(writer);
        Document document = new Document(pdfDoc);

        try {
            PdfFont titleFont = PdfFontFactory.createFont();
            PdfFont headerFont = PdfFontFactory.createFont();
            PdfFont normalFont = PdfFontFactory.createFont();

            // Title
            Paragraph title = new Paragraph("SecAINW Anomaly Detection Report")
                    .setFont(titleFont)
                    .setFontSize(20)
                    .setBold()
                    .setTextAlignment(TextAlignment.CENTER)
                    .setMarginBottom(20);
            document.add(title);

            // Report metadata
            Table metadataTable = new Table(UnitValue.createPercentArray(new float[]{30, 70}))
                    .setWidth(UnitValue.createPercentValue(100));
            
            addTableRow(metadataTable, "Report Generated:", LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")), headerFont, normalFont);
            addTableRow(metadataTable, "Event ID:", event.getEventId(), headerFont, normalFont);
            addTableRow(metadataTable, "Analysis Date:", event.getCreatedAt().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")), headerFont, normalFont);
            
            document.add(metadataTable);
            document.add(new Paragraph("\n"));

            // Event Details Section
            Paragraph eventDetailsHeader = new Paragraph("Event Details")
                    .setFont(headerFont)
                    .setFontSize(16)
                    .setBold()
                    .setMarginTop(20)
                    .setMarginBottom(10);
            document.add(eventDetailsHeader);

            Table eventTable = new Table(UnitValue.createPercentArray(new float[]{30, 70}))
                    .setWidth(UnitValue.createPercentValue(100));
            
            addTableRow(eventTable, "Event Type:", event.getEventType(), headerFont, normalFont);
            addTableRow(eventTable, "Timestamp:", event.getTimestamp().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")), headerFont, normalFont);
            addTableRow(eventTable, "Source IP:", event.getSourceIp(), headerFont, normalFont);
            
            if (event.getDestinationIp() != null) {
                addTableRow(eventTable, "Destination IP:", event.getDestinationIp(), headerFont, normalFont);
            }
            
            if (event.getDestinationPort() != null) {
                addTableRow(eventTable, "Destination Port:", event.getDestinationPort().toString(), headerFont, normalFont);
            }
            
            if (event.getProcessName() != null) {
                addTableRow(eventTable, "Process Name:", event.getProcessName(), headerFont, normalFont);
            }
            
            document.add(eventTable);
            document.add(new Paragraph("\n"));

            // Analysis Results Section
            Paragraph analysisHeader = new Paragraph("AI Analysis Results")
                    .setFont(headerFont)
                    .setFontSize(16)
                    .setBold()
                    .setMarginTop(20)
                    .setMarginBottom(10);
            document.add(analysisHeader);

            Table analysisTable = new Table(UnitValue.createPercentArray(new float[]{30, 70}))
                    .setWidth(UnitValue.createPercentValue(100));
            
            // Verdict with color coding
            Cell verdictCell = new Cell().add(new Paragraph(event.getVerdict().toString()).setFont(normalFont));
            if (event.getVerdict().toString().equals("ANOMALOUS")) {
                verdictCell.setBackgroundColor(ColorConstants.LIGHT_GRAY);
            }
            
            analysisTable.addCell(new Cell().add(new Paragraph("Verdict:").setFont(headerFont).setBold()));
            analysisTable.addCell(verdictCell);
            
            addTableRow(analysisTable, "Severity Score:", String.format("%.2f/10.0", event.getSeverityScore()), headerFont, normalFont);
            addTableRow(analysisTable, "Confidence Score:", String.format("%.2f", event.getConfidenceScore()), headerFont, normalFont);
            
            document.add(analysisTable);
            document.add(new Paragraph("\n"));

            // AI Explanation Section
            Paragraph explanationHeader = new Paragraph("AI Explanation")
                    .setFont(headerFont)
                    .setFontSize(16)
                    .setBold()
                    .setMarginTop(20)
                    .setMarginBottom(10);
            document.add(explanationHeader);

            Paragraph explanation = new Paragraph(event.getExplanation())
                    .setFont(normalFont)
                    .setTextAlignment(TextAlignment.JUSTIFIED)
                    .setMarginBottom(15);
            document.add(explanation);

            // Supporting Evidence Section
            Paragraph evidenceHeader = new Paragraph("Supporting Evidence")
                    .setFont(headerFont)
                    .setFontSize(16)
                    .setBold()
                    .setMarginTop(20)
                    .setMarginBottom(10);
            document.add(evidenceHeader);
            
            String supportingEvidenceText = event.getSupportingEvidence() != null ? event.getSupportingEvidence() : "N/A";
            Paragraph evidence = new Paragraph(supportingEvidenceText)
                    .setFont(normalFont)
                    .setTextAlignment(TextAlignment.JUSTIFIED)
                    .setMarginBottom(15);
            document.add(evidence);

            // CVE Information Section (if available)
            if (event.getCveData() != null && !event.getCveData().isEmpty()) {
                Paragraph cveHeader = new Paragraph("CVE Information")
                        .setFont(headerFont)
                        .setFontSize(16)
                        .setBold()
                        .setMarginTop(20)
                        .setMarginBottom(10);
                document.add(cveHeader);

                Paragraph cveInfo = new Paragraph(event.getCveData())
                        .setFont(normalFont)
                        .setTextAlignment(TextAlignment.JUSTIFIED)
                        .setMarginBottom(15);
                document.add(cveInfo);
            }

            // Footer
            document.add(new Paragraph("\n\n"));
            Paragraph footer = new Paragraph("This report was generated by SecAINW AI-Powered Cybersecurity Analysis System")
                    .setFont(normalFont)
                    .setFontSize(10)
                    .setTextAlignment(TextAlignment.CENTER)
                    .setFontColor(ColorConstants.GRAY);
            document.add(footer);

        } finally {
            document.close();
        }

        return baos.toByteArray();
    }

    private void addTableRow(Table table, String label, String value, PdfFont headerFont, PdfFont normalFont) {
        table.addCell(new Cell().add(new Paragraph(label).setFont(headerFont).setBold()));
        table.addCell(new Cell().add(new Paragraph(value).setFont(normalFont)));
    }

    private String uploadToS3(byte[] pdfBytes, AnomalyEvent event) {
        try {
            String fileName = String.format("reports/anomaly-report-%s-%s.pdf", 
                event.getEventId(), 
                UUID.randomUUID().toString().substring(0, 8));
            
            PutObjectRequest putObjectRequest = PutObjectRequest.builder()
                    .bucket(bucketName)
                    .key(fileName)
                    .contentType("application/pdf")
                    .contentLength((long) pdfBytes.length)
                    .build();

            PutObjectResponse response = s3Client.putObject(putObjectRequest, RequestBody.fromBytes(pdfBytes));
            
            // Generate the public URL
            String reportUrl = String.format("https://%s.s3.%s.amazonaws.com/%s", 
                bucketName, region, fileName);
            
            logger.info("Successfully uploaded report to S3: {}", reportUrl);
            return reportUrl;
            
        } catch (Exception e) {
            logger.error("Error uploading report to S3: {}", e.getMessage(), e);
            throw new RuntimeException("Failed to upload report to S3: " + e.getMessage());
        }
    }
}
