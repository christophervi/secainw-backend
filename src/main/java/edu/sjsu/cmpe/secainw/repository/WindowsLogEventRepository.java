package edu.sjsu.cmpe.secainw.repository;

import java.time.LocalDateTime;
import java.util.List;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import edu.sjsu.cmpe.secainw.model.AnomalyEvent.Verdict;
import edu.sjsu.cmpe.secainw.model.User;
import edu.sjsu.cmpe.secainw.model.WindowsLogEvent;

@Repository
public interface WindowsLogEventRepository extends JpaRepository<WindowsLogEvent, Long> {
    
    Page<WindowsLogEvent> findAllByOrderByCreatedAtDesc(Pageable pageable);
    
    List<WindowsLogEvent> findByAnalyzedByOrderByCreatedAtDesc(User analyzedBy);
    
    List<WindowsLogEvent> findByVerdictOrderByCreatedAtDesc(Verdict verdict);
    
    @Query("SELECT w FROM WindowsLogEvent w WHERE w.eventId = :eventId ORDER BY w.createdAt DESC")
    List<WindowsLogEvent> findByEventId(@Param("eventId") Integer eventId);
    
    @Query("SELECT w FROM WindowsLogEvent w WHERE w.userName = :userName ORDER BY w.createdAt DESC")
    List<WindowsLogEvent> findByUserName(@Param("userName") String userName);
    
    @Query("SELECT w FROM WindowsLogEvent w WHERE w.logHost = :logHost ORDER BY w.createdAt DESC")
    List<WindowsLogEvent> findByLogHost(@Param("logHost") String logHost);
    
    @Query("SELECT w FROM WindowsLogEvent w WHERE w.processName LIKE %:processName% ORDER BY w.createdAt DESC")
    List<WindowsLogEvent> findByProcessNameContaining(@Param("processName") String processName);
    
    @Query("SELECT w FROM WindowsLogEvent w WHERE w.severityScore >= :minScore ORDER BY w.severityScore DESC")
    List<WindowsLogEvent> findBySeverityScoreGreaterThanEqual(@Param("minScore") Double minScore);
    
    @Query("SELECT w FROM WindowsLogEvent w WHERE w.createdAt BETWEEN :startDate AND :endDate ORDER BY w.createdAt DESC")
    List<WindowsLogEvent> findByCreatedAtBetween(@Param("startDate") LocalDateTime startDate, 
                                                @Param("endDate") LocalDateTime endDate);
    
    @Query("SELECT COUNT(w) FROM WindowsLogEvent w WHERE w.verdict = :verdict")
    Long countByVerdict(@Param("verdict") Verdict verdict);
    
    @Query("SELECT AVG(w.severityScore) FROM WindowsLogEvent w WHERE w.verdict = :verdict")
    Double averageSeverityScoreByVerdict(@Param("verdict") Verdict verdict);
    
    @Query("SELECT w.eventId, COUNT(w) as count FROM WindowsLogEvent w GROUP BY w.eventId ORDER BY count DESC")
    List<Object[]> findTopEventIds();
    
    @Query("SELECT w.logHost, COUNT(w) as count FROM WindowsLogEvent w GROUP BY w.logHost ORDER BY count DESC")
    List<Object[]> findTopLogHosts();
    
    @Query("SELECT w.processName, COUNT(w) as count FROM WindowsLogEvent w WHERE w.processName IS NOT NULL GROUP BY w.processName ORDER BY count DESC")
    List<Object[]> findTopProcessNames();
    
    @Query("SELECT w FROM WindowsLogEvent w WHERE w.eventId IN (4625, 4648, 4672) ORDER BY w.createdAt DESC")
    List<WindowsLogEvent> findSuspiciousEvents();
}
