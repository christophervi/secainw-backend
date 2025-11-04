package edu.sjsu.cmpe.secainw.repository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import edu.sjsu.cmpe.secainw.model.AnomalyEvent;
import edu.sjsu.cmpe.secainw.model.User;

@Repository
public interface AnomalyEventRepository extends JpaRepository<AnomalyEvent, Long> {
    Optional<AnomalyEvent> findByEventId(String eventId);
    
    Page<AnomalyEvent> findByUserOrderByCreatedAtDesc(User user, Pageable pageable);
    
    //List<AnomalyEvent> findByAnalyzedByOrderByCreatedAtDesc(User user);
    List<AnomalyEvent> findByUserOrderByCreatedAtDesc(User user);
    
    Page<AnomalyEvent> findAllByOrderByCreatedAtDesc(Pageable pageable);
    
    @Query("SELECT ae FROM AnomalyEvent ae WHERE ae.verdict = :verdict ORDER BY ae.createdAt DESC")
    List<AnomalyEvent> findByVerdict(@Param("verdict") AnomalyEvent.Verdict verdict);
    
    List<AnomalyEvent> findByVerdictOrderByCreatedAtDesc(AnomalyEvent.Verdict verdict);
    
    @Query("SELECT ae FROM AnomalyEvent ae WHERE ae.createdAt BETWEEN :startDate AND :endDate ORDER BY ae.createdAt DESC")
    List<AnomalyEvent> findByDateRange(@Param("startDate") LocalDateTime startDate, @Param("endDate") LocalDateTime endDate);
    
    @Query("SELECT ae FROM AnomalyEvent ae WHERE ae.severityScore >= :minScore ORDER BY ae.severityScore DESC")
    List<AnomalyEvent> findBySeverityScoreGreaterThanEqual(@Param("minScore") Double minScore);
    
    @Query("SELECT COUNT(ae) FROM AnomalyEvent ae WHERE ae.verdict = 'ANOMALOUS'")
    Long countAnomalousEvents();
    
    @Query("SELECT COUNT(ae) FROM AnomalyEvent ae WHERE ae.verdict = 'NORMAL'")
    Long countNormalEvents();
    
    @Query("SELECT AVG(ae.severityScore) FROM AnomalyEvent ae WHERE ae.verdict = 'ANOMALOUS'")
    Double getAverageSeverityScore();
}
