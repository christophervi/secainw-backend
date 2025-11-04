package edu.sjsu.cmpe.secainw.repository;

import edu.sjsu.cmpe.secainw.model.AnalystFeedback;
import edu.sjsu.cmpe.secainw.model.AnomalyEvent;
import edu.sjsu.cmpe.secainw.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface AnalystFeedbackRepository extends JpaRepository<AnalystFeedback, Long> {
    List<AnalystFeedback> findByAnomalyEvent(AnomalyEvent anomalyEvent);
    
    List<AnalystFeedback> findByUser(User user);
    
    Optional<AnalystFeedback> findByAnomalyEventAndUser(AnomalyEvent anomalyEvent, User user);
    
    @Query("SELECT AVG(af.accuracyRating) FROM AnalystFeedback af")
    Double getAverageAccuracyRating();
    
    @Query("SELECT AVG(af.explanationQualityRating) FROM AnalystFeedback af")
    Double getAverageExplanationQualityRating();
    
    @Query("SELECT COUNT(af) FROM AnalystFeedback af WHERE af.isCorrectDetection = true")
    Long countCorrectDetections();
    
    @Query("SELECT COUNT(af) FROM AnalystFeedback af WHERE af.isCorrectDetection = false")
    Long countIncorrectDetections();
}
