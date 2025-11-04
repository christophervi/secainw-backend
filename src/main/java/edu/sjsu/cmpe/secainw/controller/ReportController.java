package edu.sjsu.cmpe.secainw.controller;

import edu.sjsu.cmpe.secainw.service.ReportService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/api/reports")
public class ReportController {
    @Autowired
    private ReportService reportService;

    @PostMapping("/generate/{eventId}")
    @PreAuthorize("hasRole('ANALYST') or hasRole('ADMIN')")
    public ResponseEntity<?> generateReport(@PathVariable Long eventId) {
        try {
            String reportUrl = reportService.generateAndUploadReport(eventId);
            
            Map<String, Object> response = new HashMap<>();
            response.put("message", "Report generated successfully");
            response.put("reportUrl", reportUrl);
            response.put("type", "success");
            
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            Map<String, String> errorResponse = new HashMap<>();
            errorResponse.put("message", "Error generating report: " + e.getMessage());
            errorResponse.put("type", "error");
            
            return ResponseEntity.badRequest().body(errorResponse);
        }
    }

    @GetMapping("/download/{eventId}")
    @PreAuthorize("hasRole('ANALYST') or hasRole('ADMIN') or hasRole('VIEWER')")
    public ResponseEntity<?> getReportUrl(@PathVariable Long eventId) {
        try {
            String reportUrl = reportService.generateAndUploadReport(eventId);
            
            Map<String, Object> response = new HashMap<>();
            response.put("reportUrl", reportUrl);
            response.put("type", "success");
            
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            Map<String, String> errorResponse = new HashMap<>();
            errorResponse.put("message", "Error retrieving report: " + e.getMessage());
            errorResponse.put("type", "error");
            
            return ResponseEntity.badRequest().body(errorResponse);
        }
    }
}
