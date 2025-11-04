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
import edu.sjsu.cmpe.secainw.model.NetflowEvent;
import edu.sjsu.cmpe.secainw.model.User;

@Repository
public interface NetflowEventRepository extends JpaRepository<NetflowEvent, Long> {
    
    Page<NetflowEvent> findAllByOrderByCreatedAtDesc(Pageable pageable);
    
    List<NetflowEvent> findByAnalyzedByOrderByCreatedAtDesc(User analyzedBy);
    
    List<NetflowEvent> findByVerdictOrderByCreatedAtDesc(Verdict verdict);
    
    @Query("SELECT n FROM NetflowEvent n WHERE n.srcDevice = :device OR n.dstDevice = :device ORDER BY n.createdAt DESC")
    List<NetflowEvent> findByDevice(@Param("device") String device);
    
    @Query("SELECT n FROM NetflowEvent n WHERE n.srcPort = :port OR n.dstPort = :port ORDER BY n.createdAt DESC")
    List<NetflowEvent> findByPort(@Param("port") String port);
    
    @Query("SELECT n FROM NetflowEvent n WHERE n.protocol = :protocol ORDER BY n.createdAt DESC")
    List<NetflowEvent> findByProtocol(@Param("protocol") Integer protocol);
    
    @Query("SELECT n FROM NetflowEvent n WHERE n.severityScore >= :minScore ORDER BY n.severityScore DESC")
    List<NetflowEvent> findBySeverityScoreGreaterThanEqual(@Param("minScore") Double minScore);
    
    @Query("SELECT n FROM NetflowEvent n WHERE n.createdAt BETWEEN :startDate AND :endDate ORDER BY n.createdAt DESC")
    List<NetflowEvent> findByCreatedAtBetween(@Param("startDate") LocalDateTime startDate, 
                                             @Param("endDate") LocalDateTime endDate);
    
    @Query("SELECT COUNT(n) FROM NetflowEvent n WHERE n.verdict = :verdict")
    Long countByVerdict(@Param("verdict") Verdict verdict);
    
    @Query("SELECT AVG(n.severityScore) FROM NetflowEvent n WHERE n.verdict = :verdict")
    Double averageSeverityScoreByVerdict(@Param("verdict") Verdict verdict);
    
    @Query("SELECT n.srcDevice, COUNT(n) as count FROM NetflowEvent n GROUP BY n.srcDevice ORDER BY count DESC")
    List<Object[]> findTopSourceDevices();
    
    @Query("SELECT n.dstPort, COUNT(n) as count FROM NetflowEvent n WHERE n.dstPort IS NOT NULL GROUP BY n.dstPort ORDER BY count DESC")
    List<Object[]> findTopDestinationPorts();
}
