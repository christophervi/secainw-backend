package edu.sjsu.cmpe.secainw.controller;

import edu.sjsu.cmpe.secainw.model.NetflowEvent;
import edu.sjsu.cmpe.secainw.model.User;
import edu.sjsu.cmpe.secainw.model.WindowsLogEvent;
import edu.sjsu.cmpe.secainw.repository.NetflowEventRepository;
import edu.sjsu.cmpe.secainw.repository.WindowsLogEventRepository;
import edu.sjsu.cmpe.secainw.security.UserDetailsImpl;
import edu.sjsu.cmpe.secainw.service.LanlDataImportService;
import edu.sjsu.cmpe.secainw.service.UserService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;

@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/api/lanl")
public class LanlDataController {
    private static final Logger logger = LoggerFactory.getLogger(LanlDataController.class);

    @Autowired
    private LanlDataImportService lanlDataImportService;

    @Autowired
    private UserService userService;

    @Autowired
    private NetflowEventRepository netflowEventRepository;

    @Autowired
    private WindowsLogEventRepository windowsLogEventRepository;

    @PostMapping("/import/netflow/{filename}")
    @PreAuthorize("hasRole('ANALYST') or hasRole('ADMIN')")
    public ResponseEntity<?> importNetflowData(@PathVariable String filename,
                                             Authentication authentication) {
        try {
            UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();
            User user = userService.findById(userDetails.getId())
                    .orElseThrow(() -> new RuntimeException("User not found"));

            logger.info("Starting netflow import for file: {} by user: {}", filename, user.getUsername());

            CompletableFuture<Map<String, Object>> future = 
                lanlDataImportService.importNetflowDataAsync(filename, user);

            Map<String, Object> response = new HashMap<>();
            response.put("message", "Netflow data import started");
            response.put("filename", filename);
            response.put("status", "processing");

            return ResponseEntity.ok(response);

        } catch (Exception e) {
            logger.error("Error starting netflow import: {}", e.getMessage(), e);
            return ResponseEntity.badRequest()
                    .body(Map.of("error", "Failed to start import: " + e.getMessage()));
        }
    }

    @PostMapping("/import/windows-logs/{filename}")
    @PreAuthorize("hasRole('ANALYST') or hasRole('ADMIN')")
    public ResponseEntity<?> importWindowsLogData(@PathVariable String filename,
                                                Authentication authentication) {
        try {
            UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();
            User user = userService.findById(userDetails.getId())
                    .orElseThrow(() -> new RuntimeException("User not found"));

            logger.info("Starting Windows log import for file: {} by user: {}", filename, user.getUsername());

            CompletableFuture<Map<String, Object>> future = 
                lanlDataImportService.importWindowsLogDataAsync(filename, user);

            Map<String, Object> response = new HashMap<>();
            response.put("message", "Windows log data import started");
            response.put("filename", filename);
            response.put("status", "processing");

            return ResponseEntity.ok(response);

        } catch (Exception e) {
            logger.error("Error starting Windows log import: {}", e.getMessage(), e);
            return ResponseEntity.badRequest()
                    .body(Map.of("error", "Failed to start import: " + e.getMessage()));
        }
    }

    @GetMapping("/import/status")
    @PreAuthorize("hasRole('ANALYST') or hasRole('ADMIN')")
    public ResponseEntity<?> getImportStatus() {
        try {
            Map<String, Object> status = lanlDataImportService.getImportStatus();
            return ResponseEntity.ok(status);
        } catch (Exception e) {
            logger.error("Error getting import status: {}", e.getMessage(), e);
            return ResponseEntity.badRequest()
                    .body(Map.of("error", "Failed to get status: " + e.getMessage()));
        }
    }

    @GetMapping("/netflow")
    @PreAuthorize("hasRole('ANALYST') or hasRole('ADMIN')")
    public ResponseEntity<?> getNetflowEvents(@RequestParam(defaultValue = "0") int page,
                                            @RequestParam(defaultValue = "20") int size) {
        try {
            Pageable pageable = PageRequest.of(page, size);
            Page<NetflowEvent> events = netflowEventRepository.findAllByOrderByCreatedAtDesc(pageable);
            
            Map<String, Object> response = new HashMap<>();
            response.put("events", events.getContent());
            response.put("totalElements", events.getTotalElements());
            response.put("totalPages", events.getTotalPages());
            response.put("currentPage", page);
            response.put("size", size);

            return ResponseEntity.ok(response);

        } catch (Exception e) {
            logger.error("Error retrieving netflow events: {}", e.getMessage(), e);
            return ResponseEntity.badRequest()
                    .body(Map.of("error", "Failed to retrieve events: " + e.getMessage()));
        }
    }

    @GetMapping("/windows-logs")
    @PreAuthorize("hasRole('ANALYST') or hasRole('ADMIN')")
    public ResponseEntity<?> getWindowsLogEvents(@RequestParam(defaultValue = "0") int page,
                                               @RequestParam(defaultValue = "20") int size) {
        try {
            Pageable pageable = PageRequest.of(page, size);
            Page<WindowsLogEvent> events = windowsLogEventRepository.findAllByOrderByCreatedAtDesc(pageable);
            
            Map<String, Object> response = new HashMap<>();
            response.put("events", events.getContent());
            response.put("totalElements", events.getTotalElements());
            response.put("totalPages", events.getTotalPages());
            response.put("currentPage", page);
            response.put("size", size);

            return ResponseEntity.ok(response);

        } catch (Exception e) {
            logger.error("Error retrieving Windows log events: {}", e.getMessage(), e);
            return ResponseEntity.badRequest()
                    .body(Map.of("error", "Failed to retrieve events: " + e.getMessage()));
        }
    }

    @GetMapping("/netflow/{id}")
    @PreAuthorize("hasRole('ANALYST') or hasRole('ADMIN')")
    public ResponseEntity<?> getNetflowEvent(@PathVariable Long id) {
        try {
            return netflowEventRepository.findById(id)
                    .map(event -> ResponseEntity.ok().body(event))
                    .orElse(ResponseEntity.notFound().build());
        } catch (Exception e) {
            logger.error("Error retrieving netflow event {}: {}", id, e.getMessage(), e);
            return ResponseEntity.badRequest()
                    .body(Map.of("error", "Failed to retrieve event: " + e.getMessage()));
        }
    }

    @GetMapping("/windows-logs/{id}")
    @PreAuthorize("hasRole('ANALYST') or hasRole('ADMIN')")
    public ResponseEntity<?> getWindowsLogEvent(@PathVariable Long id) {
        try {
            return windowsLogEventRepository.findById(id)
                    .map(event -> ResponseEntity.ok().body(event))
                    .orElse(ResponseEntity.notFound().build());
        } catch (Exception e) {
            logger.error("Error retrieving Windows log event {}: {}", id, e.getMessage(), e);
            return ResponseEntity.badRequest()
                    .body(Map.of("error", "Failed to retrieve event: " + e.getMessage()));
        }
    }

    @GetMapping("/statistics")
    @PreAuthorize("hasRole('ANALYST') or hasRole('ADMIN')")
    public ResponseEntity<?> getStatistics() {
        try {
            Map<String, Object> stats = new HashMap<>();
            
            // Netflow statistics
            long totalNetflowEvents = netflowEventRepository.count();
            List<Object[]> topSourceDevices = netflowEventRepository.findTopSourceDevices();
            List<Object[]> topDestinationPorts = netflowEventRepository.findTopDestinationPorts();
            
            // Windows log statistics
            long totalWindowsLogEvents = windowsLogEventRepository.count();
            List<Object[]> topEventIds = windowsLogEventRepository.findTopEventIds();
            List<Object[]> topLogHosts = windowsLogEventRepository.findTopLogHosts();
            List<Object[]> topProcessNames = windowsLogEventRepository.findTopProcessNames();
            
            stats.put("netflow", Map.of(
                "totalEvents", totalNetflowEvents,
                "topSourceDevices", topSourceDevices,
                "topDestinationPorts", topDestinationPorts
            ));
            
            stats.put("windowsLogs", Map.of(
                "totalEvents", totalWindowsLogEvents,
                "topEventIds", topEventIds,
                "topLogHosts", topLogHosts,
                "topProcessNames", topProcessNames
            ));

            return ResponseEntity.ok(stats);

        } catch (Exception e) {
            logger.error("Error retrieving statistics: {}", e.getMessage(), e);
            return ResponseEntity.badRequest()
                    .body(Map.of("error", "Failed to retrieve statistics: " + e.getMessage()));
        }
    }

    @GetMapping("/available-files")
    @PreAuthorize("hasRole('ANALYST') or hasRole('ADMIN')")
    public ResponseEntity<?> getAvailableFiles() {
        try {
            Map<String, Object> files = new HashMap<>();
            
            // List available LANL dataset files
            files.put("netflow", List.of(
                "netflow_day-02.bz2",
                "netflow_day-03.bz2"
            ));
            
            files.put("windowsLogs", List.of(
                "wls_day-02.bz2",
                "wls_day-03.bz2"
            ));

            return ResponseEntity.ok(files);

        } catch (Exception e) {
            logger.error("Error retrieving available files: {}", e.getMessage(), e);
            return ResponseEntity.badRequest()
                    .body(Map.of("error", "Failed to retrieve files: " + e.getMessage()));
        }
    }
}
