package com.simpath.app;

import com.simpath.app.token.refresh.service.TokenCleanupBatchService;
import com.simpath.app.token.refresh.service.TokenCleanupService;
import org.junit.jupiter.api.Test;
import java.time.Instant;
import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;

class TokenCleanupServiceTest {
    private final TokenCleanupBatchService batches = mock(TokenCleanupBatchService.class);

    @Test void stopsAtConfiguredBatchCap() {
        when(batches.deleteBatch(any(), eq(100))).thenReturn(100);
        new TokenCleanupService(batches, true, 30, 100, 3, 5).cleanup();
        verify(batches, times(3)).deleteBatch(any(), eq(100));
    }

    @Test void stopsAfterShortBatchAndKeepsOneCutoff() {
        when(batches.deleteBatch(any(), eq(100))).thenReturn(100, 2);
        new TokenCleanupService(batches, true, 30, 100, 10, 5).cleanup();
        org.mockito.ArgumentCaptor<Instant> cutoffs = org.mockito.ArgumentCaptor.forClass(Instant.class);
        verify(batches, times(2)).deleteBatch(cutoffs.capture(), eq(100));
        assertThat(cutoffs.getAllValues().get(0)).isEqualTo(cutoffs.getAllValues().get(1));
    }

    @Test void disabledCleanupDoesNoWork() {
        new TokenCleanupService(batches, false, 30, 100, 10, 5).cleanup();
        verifyNoInteractions(batches);
    }

    @Test void stopsOnBatchFailureRatherThanLooping() {
        when(batches.deleteBatch(any(), eq(100))).thenReturn(100).thenThrow(new IllegalStateException("database unavailable"));
        assertThatThrownBy(() -> new TokenCleanupService(batches, true, 30, 100, 10, 5).cleanup())
                .isInstanceOf(IllegalStateException.class);
        verify(batches, times(2)).deleteBatch(any(), eq(100));
    }
}
